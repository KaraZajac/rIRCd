mod format;
mod message;
mod parser;

pub use format::{
    add_batch_tag, add_tags_for_recipient, format_message, format_message_within, generate_msgid,
    server_time_now, to_server_time, truncate_bytes, SenderTags,
};
pub use message::Message;
pub use parser::{parse_message, parse_message_with_limit, ParseError, DEFAULT_MAX_MESSAGE_BODY};
