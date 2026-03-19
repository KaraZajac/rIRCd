mod format;
mod message;
mod parser;

pub use format::{add_batch_tag, add_tags_for_recipient, format_message, generate_msgid};
pub use message::Message;
pub use parser::{parse_message, ParseError};
