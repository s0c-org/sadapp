use crate::{LogEvent, windows};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{self, Read},
    mem,
    path::PathBuf,
    ptr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_EVT_QUERY_RESULT_INVALID_POSITION, ERROR_EVT_QUERY_RESULT_STALE,
        ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND,
    },
    System::EventLog::*,
};

const CHANNELS: [&str; 2] = ["System", "Application"];
const MAX_EVENTS: usize = 80;
const MAX_BUFFER_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: usize = 1024 * 1024;
const FIRST_QUERY: &str =
    "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= 900000]]]";
const RESUME_QUERY: &str = "*[System[(Level=1 or Level=2 or Level=3)]]";
static COLLECTOR: OnceLock<Mutex<Option<EventCollector>>> = OnceLock::new();

struct Handle(EVT_HANDLE);

impl Handle {
    fn new(raw: EVT_HANDLE) -> io::Result<Self> {
        if raw == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if unsafe { EvtClose(self.0) } == 0 {
            windows::write_log(&format!(
                "Cannot close Event Log handle: {}",
                io::Error::last_os_error()
            ));
        }
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn render_text(handle: EVT_HANDLE, flag: u32) -> io::Result<String> {
    let mut used = 0;
    let mut count = 0;
    unsafe {
        EvtRender(0, handle, flag, 0, ptr::null_mut(), &mut used, &mut count);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if used as usize > MAX_BUFFER_BYTES {
        return Err(io::Error::other(
            "Event bookmark exceeds the 64 KiB render budget",
        ));
    }
    let mut buffer = vec![0_u16; (used as usize).div_ceil(2)];
    if unsafe {
        EvtRender(
            0,
            handle,
            flag,
            used,
            buffer.as_mut_ptr().cast(),
            &mut used,
            &mut count,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

fn variant<'a>(
    values: &'a [EVT_VARIANT],
    index: i32,
    expected_type: i32,
) -> io::Result<&'a EVT_VARIANT> {
    values
        .get(index as usize)
        .filter(|value| value.Type == expected_type as u32)
        .ok_or_else(|| {
            io::Error::other(format!("Missing or invalid Windows event property {index}"))
        })
}

fn formatted_message(event: EVT_HANDLE, provider: &str) -> io::Result<String> {
    let provider = wide(provider);
    let metadata =
        Handle::new(unsafe { EvtOpenPublisherMetadata(0, provider.as_ptr(), ptr::null(), 0, 0) })?;
    let mut used = 0;
    unsafe {
        EvtFormatMessage(
            metadata.0,
            event,
            0,
            0,
            ptr::null(),
            EvtFormatMessageEvent,
            0,
            ptr::null_mut(),
            &mut used,
        );
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if used as usize > MAX_BUFFER_BYTES / 2 {
        return Err(io::Error::other(
            "Event message exceeds the 64 KiB render budget",
        ));
    }
    let mut buffer = vec![0_u16; used as usize];
    if unsafe {
        EvtFormatMessage(
            metadata.0,
            event,
            0,
            0,
            ptr::null(),
            EvtFormatMessageEvent,
            used,
            buffer.as_mut_ptr(),
            &mut used,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    let mut message = String::from_utf16_lossy(&buffer[..length]);
    if message.trim().is_empty() {
        return Err(io::Error::other(
            "The event provider returned an empty message",
        ));
    }
    if message.len() > 4000 {
        message.truncate(message.floor_char_boundary(3984));
        message.push_str(" [truncated]");
    }
    Ok(message)
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    channel: String,
    bookmark: String,
    event: LogEvent,
}

fn severity(level: u8) -> io::Result<&'static str> {
    match level {
        1 => Ok("critical"),
        2 => Ok("error"),
        3 => Ok("warn"),
        _ => Err(io::Error::other(
            "Event Log query returned an unrequested severity",
        )),
    }
}

fn decode_event(event: EVT_HANDLE, context: EVT_HANDLE, channel: &str) -> io::Result<Record> {
    let mut used = 0;
    let mut count = 0;
    unsafe {
        EvtRender(
            context,
            event,
            EvtRenderEventValues,
            0,
            ptr::null_mut(),
            &mut used,
            &mut count,
        );
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if used as usize > MAX_BUFFER_BYTES {
        return Err(io::Error::other(
            "Windows event properties exceed the 64 KiB render budget",
        ));
    }
    let mut buffer = vec![0_u64; (used as usize).div_ceil(8)];
    if unsafe {
        EvtRender(
            context,
            event,
            EvtRenderEventValues,
            used,
            buffer.as_mut_ptr().cast(),
            &mut used,
            &mut count,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if count as usize > mem::size_of_val(buffer.as_slice()) / mem::size_of::<EVT_VARIANT>() {
        return Err(io::Error::other("Truncated Windows event property array"));
    }
    let values = unsafe {
        std::slice::from_raw_parts(buffer.as_ptr().cast::<EVT_VARIANT>(), count as usize)
    };
    let provider_pointer = unsafe {
        variant(values, EvtSystemProviderName, EvtVarTypeString)?
            .Anonymous
            .StringVal
    };
    // EvtRender owns the string in this buffer; verify its bounds before decoding.
    let start = provider_pointer as usize;
    let buffer_start = buffer.as_ptr() as usize;
    let buffer_end = buffer_start + mem::size_of_val(buffer.as_slice());
    if start < buffer_start || start >= buffer_end || start % 2 != 0 {
        return Err(io::Error::other("Invalid Windows event provider string"));
    }
    let text = unsafe { std::slice::from_raw_parts(provider_pointer, (buffer_end - start) / 2) };
    let length = text
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(|| io::Error::other("Unterminated event provider"))?;
    let provider = String::from_utf16_lossy(&text[..length]);
    let event_id = unsafe {
        variant(values, EvtSystemEventID, EvtVarTypeUInt16)?
            .Anonymous
            .UInt16Val
    };
    let record_id = unsafe {
        variant(values, EvtSystemEventRecordId, EvtVarTypeUInt64)?
            .Anonymous
            .UInt64Val
    };
    let level = unsafe {
        variant(values, EvtSystemLevel, EvtVarTypeByte)?
            .Anonymous
            .ByteVal
    };
    let file_time = unsafe {
        variant(values, EvtSystemTimeCreated, EvtVarTypeFileTime)?
            .Anonymous
            .FileTimeVal
    };
    let timestamp = file_time
        .checked_sub(116_444_736_000_000_000)
        .ok_or_else(|| io::Error::other("Windows event timestamp predates Unix epoch"))?
        / 10_000_000;
    let message = formatted_message(event, &provider).unwrap_or_else(|error| {
        format!("Windows event {event_id} from {provider}. Message unavailable: {error}")
    });
    let bookmark = Handle::new(unsafe { EvtCreateBookmark(ptr::null()) })?;
    if unsafe { EvtUpdateBookmark(bookmark.0, event) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Record {
        channel: channel.into(),
        bookmark: render_text(bookmark.0, EvtRenderBookmark)?,
        event: LogEvent {
            timestamp,
            source: provider.chars().take(120).collect(),
            severity: severity(level)?.into(),
            message,
            fingerprint: Some(format!(
                "windows:{channel}:{provider}:{event_id}:{record_id}"
            )),
            container_id: None,
            container_name: None,
            unit: Some(format!("{channel} / Event ID {event_id}")),
            journal_cursor: None,
        },
    })
}

fn query(
    channel: &str,
    bookmark: Option<&str>,
    limit: usize,
) -> io::Result<(Vec<Record>, Option<String>)> {
    query_with_filter(channel, bookmark, limit, FIRST_QUERY, RESUME_QUERY)
}

fn query_with_filter(
    channel: &str,
    bookmark: Option<&str>,
    limit: usize,
    first_query: &str,
    resume_query: &str,
) -> io::Result<(Vec<Record>, Option<String>)> {
    let path = wide(channel);
    let xpath = wide(if bookmark.is_some() {
        resume_query
    } else {
        first_query
    });
    let result = Handle::new(unsafe {
        EvtQuery(
            0,
            path.as_ptr(),
            xpath.as_ptr(),
            EvtQueryChannelPath | EvtQueryForwardDirection,
        )
    })?;
    if let Some(bookmark) = bookmark {
        let bookmark = wide(bookmark);
        let bookmark = Handle::new(unsafe { EvtCreateBookmark(bookmark.as_ptr()) })?;
        if unsafe {
            EvtSeek(
                result.0,
                0,
                bookmark.0,
                0,
                EvtSeekRelativeToBookmark | EvtSeekStrict,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            // Stale bookmarks are expected after retention/clear, not after access or I/O errors.
            if matches!(error.raw_os_error(), Some(code) if [ERROR_EVT_QUERY_RESULT_STALE, ERROR_EVT_QUERY_RESULT_INVALID_POSITION, ERROR_NOT_FOUND].contains(&(code as u32)))
            {
                let (events, _) =
                    query_with_filter(channel, None, limit, first_query, resume_query)?;
                return Ok((
                    events,
                    Some(format!(
                        "{channel} bookmark expired or the log was cleared ({error}); resumed with a 15-minute lookback"
                    )),
                ));
            }
            return Err(error);
        }
        // Consume the bookmarked event, including when it is the latest matching record.
        let mut raw = 0;
        let mut returned = 0;
        if unsafe { EvtNext(result.0, 1, &mut raw, 100, 0, &mut returned) } == 0 {
            return Err(io::Error::last_os_error());
        }
        drop(Handle::new(raw)?);
    }
    let context =
        Handle::new(unsafe { EvtCreateRenderContext(0, ptr::null(), EvtRenderContextSystem) })?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut records = Vec::new();
    while records.len() < limit && Instant::now() < deadline {
        let mut raw = 0;
        let mut returned = 0;
        if unsafe { EvtNext(result.0, 1, &mut raw, 100, 0, &mut returned) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                break;
            }
            return Err(error);
        }
        let event = Handle::new(raw)?;
        records.push(decode_event(event.0, context.0, channel)?);
    }
    Ok((records, None))
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct State {
    bookmarks: BTreeMap<String, String>,
    pending: Vec<Record>,
    #[serde(default)]
    last_acknowledged: Vec<String>,
    #[serde(default)]
    warning: Option<String>,
}

struct EventCollector {
    path: Option<PathBuf>,
    state: State,
}

impl EventCollector {
    fn open(path: Option<PathBuf>) -> io::Result<Self> {
        let state = match path
            .as_ref()
            .map(|path| {
                let file = std::fs::File::open(path)?;
                let mut bytes = Vec::new();
                file.take((MAX_STATE_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)?;
                Ok::<_, io::Error>(bytes)
            })
            .transpose()
        {
            Ok(Some(bytes)) => {
                if bytes.len() > MAX_STATE_BYTES {
                    return Err(io::Error::other("Event Log state exceeds the 1 MiB budget"));
                }
                let state: State = serde_json::from_slice(&bytes).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Invalid Event Log state: {error}"),
                    )
                })?;
                if state.pending.len() > MAX_EVENTS
                    || state.last_acknowledged.len() > MAX_EVENTS
                    || state
                        .pending
                        .iter()
                        .any(|record| !CHANNELS.contains(&record.channel.as_str()))
                    || state
                        .bookmarks
                        .keys()
                        .any(|channel| !CHANNELS.contains(&channel.as_str()))
                {
                    return Err(io::Error::other(
                        "Invalid Event Log state bounds or channels",
                    ));
                }
                state
            }
            Ok(None) => State::default(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => State::default(),
            Err(error) => return Err(error),
        };
        Ok(Self { path, state })
    }

    fn persist(&self, state: &State) -> io::Result<()> {
        if let Some(path) = &self.path {
            let bytes = serde_json::to_vec(state)?;
            if bytes.len() > MAX_STATE_BYTES {
                return Err(io::Error::other("Event Log state exceeds the 1 MiB budget"));
            }
            windows::atomic_write(path, &bytes, false)?;
        }
        Ok(())
    }

    fn events(&self) -> io::Result<Vec<LogEvent>> {
        self.state
            .pending
            .iter()
            .map(|record| {
                let mut event = record.event.clone();
                event.journal_cursor = Some(serde_json::to_string(&(
                    record.channel.clone(),
                    record.bookmark.clone(),
                ))?);
                Ok(event)
            })
            .collect()
    }

    fn collect(&mut self, max_events: usize) -> io::Result<(Vec<LogEvent>, Option<String>)> {
        if !self.state.pending.is_empty() {
            return Ok((self.events()?, self.state.warning.clone()));
        }
        let mut next = self.state.clone();
        let mut warnings = Vec::new();
        for channel in CHANNELS {
            match query(
                channel,
                next.bookmarks.get(channel).map(String::as_str),
                max_events.min(MAX_EVENTS) / CHANNELS.len(),
            ) {
                Ok((records, warning)) => {
                    next.pending.extend(records);
                    warnings.extend(warning);
                }
                Err(error) => {
                    warnings.push(format!("{channel} Event Log collection failed: {error}"))
                }
            }
        }
        // Persist the batch before exposure: retries/restarts must not lose events or advance a bookmark before acknowledgement.
        next.warning = (!warnings.is_empty()).then(|| warnings.join("; "));
        self.persist(&next)?;
        self.state = next;
        Ok((self.events()?, self.state.warning.clone()))
    }

    fn acknowledge(&mut self, events: &[LogEvent]) -> io::Result<()> {
        let cursors: Vec<String> = events
            .iter()
            .filter_map(|event| event.journal_cursor.clone())
            .collect();
        if !cursors.is_empty()
            && cursors.len() == events.len()
            && cursors == self.state.last_acknowledged
        {
            return Ok(());
        }
        let expected = self.events()?;
        if expected.is_empty()
            || events.len() != expected.len()
            || !events
                .iter()
                .zip(&expected)
                .all(|(event, saved)| event.journal_cursor == saved.journal_cursor)
        {
            return Err(io::Error::other(
                "Cannot acknowledge an unrelated Windows Event Log batch",
            ));
        }
        let mut next = self.state.clone();
        for record in next.pending.drain(..) {
            next.bookmarks.insert(record.channel, record.bookmark);
        }
        next.last_acknowledged = cursors;
        next.warning = None;
        self.persist(&next)?;
        self.state = next;
        Ok(())
    }
}

fn with_collector<T>(
    operation: impl FnOnce(&mut EventCollector) -> io::Result<T>,
) -> io::Result<T> {
    let mut guard = COLLECTOR
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| io::Error::other("Windows Event Log collector lock poisoned"))?;
    if guard.is_none() {
        let path = if windows::is_service() {
            Some(windows::state_dir()?.join("state/event-log-state.json"))
        } else {
            None
        };
        *guard = Some(EventCollector::open(path)?);
    }
    operation(guard.as_mut().expect("Event Log collector initialized"))
}

pub fn collect(max_events: usize) -> io::Result<(Vec<LogEvent>, Option<String>)> {
    with_collector(|collector| collector.collect(max_events))
}

pub fn acknowledge(events: &[LogEvent]) -> io::Result<()> {
    with_collector(|collector| collector.acknowledge(events))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Record {
        Record {
            channel: "System".into(),
            bookmark: "<BookmarkList><Bookmark Channel='System' RecordId='1' IsCurrent='true'/></BookmarkList>".into(),
            event: LogEvent {
                timestamp: 100, source: "fixture".into(), severity: "warn".into(),
                message: "Synthetic Windows event".into(), fingerprint: Some("fixture:1".into()),
                container_id: None, container_name: None, unit: Some("System / Event ID 1".into()), journal_cursor: None,
            },
        }
    }

    #[test]
    fn pending_events_replay_until_acknowledged_and_bookmarks_never_advance_early() {
        let mut reader = EventCollector::open(None).unwrap();
        reader.state.pending.push(fixture());
        let first = reader.events().unwrap();
        let repeated = reader.collect(MAX_EVENTS).unwrap().0;
        assert_eq!(first[0].journal_cursor, repeated[0].journal_cursor);
        assert!(reader.state.bookmarks.is_empty());
        assert!(reader.acknowledge(&[]).is_err());
        reader.acknowledge(&first).unwrap();
        assert!(reader.state.pending.is_empty());
        assert!(reader.state.bookmarks.contains_key("System"));
        reader.acknowledge(&first).unwrap();
        let mut later = fixture();
        later.bookmark = "later".into();
        reader.state.pending.push(later);
        reader.acknowledge(&first).unwrap();
        assert_eq!(reader.state.pending.len(), 1);
    }

    #[test]
    fn serialized_pending_batch_survives_restart_without_sending_internal_bookmarks() {
        let state = State {
            pending: vec![fixture()],
            ..State::default()
        };
        let bytes = serde_json::to_vec(&state).unwrap();
        let restored: State = serde_json::from_slice(&bytes).unwrap();
        let reader = EventCollector {
            path: None,
            state: restored,
        };
        let events = reader.events().unwrap();
        assert_eq!(events[0].message, "Synthetic Windows event");
        assert!(events[0].journal_cursor.is_some());
        let payload = serde_json::to_value(&events[0]).unwrap();
        assert!(payload.get("journal_cursor").is_none());
    }

    #[test]
    fn maps_only_requested_severities_and_queries_real_channels_without_mutating_them() {
        assert_eq!(severity(1).unwrap(), "critical");
        assert_eq!(severity(2).unwrap(), "error");
        assert_eq!(severity(3).unwrap(), "warn");
        assert!(severity(4).is_err());
        for channel in CHANNELS {
            let (records, _) =
                query_with_filter(channel, None, 2, RESUME_QUERY, RESUME_QUERY).unwrap();
            assert!(records.len() <= 2);
            if records.len() == 2 {
                let (resumed, warning) = query_with_filter(
                    channel,
                    Some(&records[0].bookmark),
                    1,
                    RESUME_QUERY,
                    RESUME_QUERY,
                )
                .unwrap();
                assert!(warning.is_none());
                assert_eq!(resumed.len(), 1);
                assert_eq!(resumed[0].bookmark, records[1].bookmark);
            }
            for record in records {
                assert!(record.event.timestamp > 0);
                assert!(!record.bookmark.is_empty());
                assert!(record.event.unit.unwrap().starts_with(channel));
            }
        }
    }

    #[test]
    fn invalid_channels_and_bookmarks_are_reported() {
        assert!(query("Sadapp-Nonexistent-Channel-Fixture", None, 1).is_err());
        assert!(query("Application", Some("not a bookmark"), 1).is_err());
    }

    #[test]
    fn failed_checkpoint_write_does_not_discard_pending_events() {
        let directory =
            std::env::temp_dir().join(format!("sadapp-eventlog-missing-{}", std::process::id()));
        assert!(!directory.exists());
        let mut reader = EventCollector {
            path: Some(directory.join("state.json")),
            state: State {
                pending: vec![fixture()],
                ..State::default()
            },
        };
        let events = reader.events().unwrap();
        assert!(reader.acknowledge(&events).is_err());
        assert_eq!(reader.state.pending.len(), 1);
        assert!(reader.state.bookmarks.is_empty());
    }

    #[test]
    fn pending_warnings_are_not_silently_cleared_on_retry() {
        let mut reader = EventCollector::open(None).unwrap();
        reader.state.pending.push(fixture());
        reader.state.warning = Some("System access denied".into());
        let (_, warning) = reader.collect(MAX_EVENTS).unwrap();
        assert_eq!(warning.as_deref(), Some("System access denied"));
    }

    #[test]
    fn malformed_persisted_state_is_not_silently_reset() {
        let path = std::env::temp_dir().join(format!(
            "sadapp-eventlog-corrupt-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, b"not-json").unwrap();
        assert!(EventCollector::open(Some(path.clone())).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn protected_delivery_state_reopens_and_commits_after_acknowledgement() {
        let directory =
            std::env::temp_dir().join(format!("sadapp-eventlog-state-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("state.json");
        let mut reader = EventCollector::open(Some(path.clone())).unwrap();
        reader.state.pending.push(fixture());
        reader.persist(&reader.state).unwrap();
        let mut restored = EventCollector::open(Some(path.clone())).unwrap();
        let events = restored.events().unwrap();
        assert_eq!(events[0].message, "Synthetic Windows event");
        restored.acknowledge(&events).unwrap();
        let committed = EventCollector::open(Some(path.clone())).unwrap();
        assert!(committed.state.pending.is_empty());
        assert!(committed.state.bookmarks.contains_key("System"));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn native_fixture_preserves_message_and_resumes_after_the_last_event() {
        if std::env::var("SADAPP_TEST_EVENTLOG_FIXTURE").as_deref() != Ok("1") {
            return;
        }
        let xpath =
            "*[System[Provider[@Name='SadappCollectorTest'] and (Level=1 or Level=2 or Level=3)]]";
        let (records, warning) = query_with_filter("Application", None, 40, xpath, xpath).unwrap();
        assert!(warning.is_none());
        assert_eq!(records.len(), 2);
        assert!(
            records[0]
                .event
                .message
                .contains("Sadapp collector warning fixture")
        );
        assert_eq!(records[0].event.severity, "warn");
        assert!(
            records[1]
                .event
                .message
                .contains("Sadapp collector error fixture")
        );
        assert_eq!(records[1].event.severity, "error");
        assert_eq!(records[0].event.source, "SadappCollectorTest");
        let (resumed, warning) =
            query_with_filter("Application", Some(&records[0].bookmark), 40, xpath, xpath).unwrap();
        assert!(warning.is_none());
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].event.message, records[1].event.message);
        let (empty, warning) =
            query_with_filter("Application", Some(&records[1].bookmark), 40, xpath, xpath).unwrap();
        assert!(warning.is_none());
        assert!(empty.is_empty());
        let expired = "<BookmarkList><Bookmark Channel='Application' RecordId='9000000000' IsCurrent='true'/></BookmarkList>";
        let (recovered, warning) =
            query_with_filter("Application", Some(expired), 40, xpath, xpath).unwrap();
        assert!(
            warning
                .unwrap()
                .contains("bookmark expired or the log was cleared")
        );
        assert_eq!(recovered.len(), 2);
    }
}
