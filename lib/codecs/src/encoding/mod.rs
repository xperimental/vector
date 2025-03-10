//! A collection of support structures that are used in the process of encoding
//! events into bytes.

pub mod format;
pub mod framing;

use std::fmt::Debug;

use bytes::BytesMut;
pub use format::{
    AvroSerializer, AvroSerializerConfig, AvroSerializerOptions, GelfSerializer,
    GelfSerializerConfig, JsonSerializer, JsonSerializerConfig, LogfmtSerializer,
    LogfmtSerializerConfig, NativeJsonSerializer, NativeJsonSerializerConfig, NativeSerializer,
    NativeSerializerConfig, RawMessageSerializer, RawMessageSerializerConfig, TextSerializer,
    TextSerializerConfig, SyslogSerializer, SyslogSerializerConfig,
};
pub use framing::{
    BoxedFramer, BoxedFramingError, BytesEncoder, BytesEncoderConfig, CharacterDelimitedEncoder,
    CharacterDelimitedEncoderConfig, CharacterDelimitedEncoderOptions, LengthDelimitedEncoder,
    LengthDelimitedEncoderConfig, NewlineDelimitedEncoder, NewlineDelimitedEncoderConfig,
};
use vector_config::configurable_component;
use vector_core::{config::DataType, event::Event, schema};

/// An error that occurred while building an encoder.
pub type BuildError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// An error that occurred while encoding structured events into byte frames.
#[derive(Debug)]
pub enum Error {
    /// The error occurred while encoding the byte frame boundaries.
    FramingError(BoxedFramingError),
    /// The error occurred while serializing a structured event into bytes.
    SerializingError(vector_common::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FramingError(error) => write!(formatter, "FramingError({})", error),
            Self::SerializingError(error) => write!(formatter, "SerializingError({})", error),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::FramingError(Box::new(error))
    }
}

/// Framing configuration.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
#[serde(tag = "method", rename_all = "snake_case")]
#[configurable(metadata(docs::enum_tag_description = "The framing method."))]
pub enum FramingConfig {
    /// Event data is not delimited at all.
    Bytes,

    /// Event data is delimited by a single ASCII (7-bit) character.
    CharacterDelimited {
        /// Options for the character delimited encoder.
        character_delimited: CharacterDelimitedEncoderOptions,
    },

    /// Event data is prefixed with its length in bytes.
    ///
    /// The prefix is a 32-bit unsigned integer, little endian.
    LengthDelimited,

    /// Event data is delimited by a newline (LF) character.
    NewlineDelimited,
}

impl From<BytesEncoderConfig> for FramingConfig {
    fn from(_: BytesEncoderConfig) -> Self {
        Self::Bytes
    }
}

impl From<CharacterDelimitedEncoderConfig> for FramingConfig {
    fn from(config: CharacterDelimitedEncoderConfig) -> Self {
        Self::CharacterDelimited {
            character_delimited: config.character_delimited,
        }
    }
}

impl From<LengthDelimitedEncoderConfig> for FramingConfig {
    fn from(_: LengthDelimitedEncoderConfig) -> Self {
        Self::LengthDelimited
    }
}

impl From<NewlineDelimitedEncoderConfig> for FramingConfig {
    fn from(_: NewlineDelimitedEncoderConfig) -> Self {
        Self::NewlineDelimited
    }
}

impl FramingConfig {
    /// Build the `Framer` from this configuration.
    pub fn build(&self) -> Framer {
        match self {
            FramingConfig::Bytes => Framer::Bytes(BytesEncoderConfig.build()),
            FramingConfig::CharacterDelimited {
                character_delimited,
            } => Framer::CharacterDelimited(
                CharacterDelimitedEncoderConfig {
                    character_delimited: character_delimited.clone(),
                }
                .build(),
            ),
            FramingConfig::LengthDelimited => {
                Framer::LengthDelimited(LengthDelimitedEncoderConfig.build())
            }
            FramingConfig::NewlineDelimited => {
                Framer::NewlineDelimited(NewlineDelimitedEncoderConfig.build())
            }
        }
    }
}

/// Produce a byte stream from byte frames.
#[derive(Debug, Clone)]
pub enum Framer {
    /// Uses a `BytesEncoder` for framing.
    Bytes(BytesEncoder),
    /// Uses a `CharacterDelimitedEncoder` for framing.
    CharacterDelimited(CharacterDelimitedEncoder),
    /// Uses a `LengthDelimitedEncoder` for framing.
    LengthDelimited(LengthDelimitedEncoder),
    /// Uses a `NewlineDelimitedEncoder` for framing.
    NewlineDelimited(NewlineDelimitedEncoder),
    /// Uses an opaque `Encoder` implementation for framing.
    Boxed(BoxedFramer),
}

impl From<BytesEncoder> for Framer {
    fn from(encoder: BytesEncoder) -> Self {
        Self::Bytes(encoder)
    }
}

impl From<CharacterDelimitedEncoder> for Framer {
    fn from(encoder: CharacterDelimitedEncoder) -> Self {
        Self::CharacterDelimited(encoder)
    }
}

impl From<LengthDelimitedEncoder> for Framer {
    fn from(encoder: LengthDelimitedEncoder) -> Self {
        Self::LengthDelimited(encoder)
    }
}

impl From<NewlineDelimitedEncoder> for Framer {
    fn from(encoder: NewlineDelimitedEncoder) -> Self {
        Self::NewlineDelimited(encoder)
    }
}

impl From<BoxedFramer> for Framer {
    fn from(encoder: BoxedFramer) -> Self {
        Self::Boxed(encoder)
    }
}

impl tokio_util::codec::Encoder<()> for Framer {
    type Error = BoxedFramingError;

    fn encode(&mut self, _: (), buffer: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Framer::Bytes(framer) => framer.encode((), buffer),
            Framer::CharacterDelimited(framer) => framer.encode((), buffer),
            Framer::LengthDelimited(framer) => framer.encode((), buffer),
            Framer::NewlineDelimited(framer) => framer.encode((), buffer),
            Framer::Boxed(framer) => framer.encode((), buffer),
        }
    }
}

/// Serializer configuration.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(tag = "codec", rename_all = "snake_case")]
#[configurable(metadata(docs::enum_tag_description = "The codec to use for encoding events."))]
pub enum SerializerConfig {
    /// Encodes an event as an [Apache Avro][apache_avro] message.
    ///
    /// [apache_avro]: https://avro.apache.org/
    Avro {
        /// Apache Avro-specific encoder options.
        avro: AvroSerializerOptions,
    },

    /// Encodes an event as a [GELF][gelf] message.
    ///
    /// [gelf]: https://docs.graylog.org/docs/gelf
    Gelf,

    /// Encodes an event as [JSON][json].
    ///
    /// [json]: https://www.json.org/
    Json(
        /// Encoding options specific to the text serializer.
        JsonSerializerConfig,
    ),

    /// Encodes an event as a [logfmt][logfmt] message.
    ///
    /// [logfmt]: https://brandur.org/logfmt
    Logfmt,

    /// Encodes an event in Vector’s [native Protocol Buffers format][vector_native_protobuf].
    ///
    /// This codec is **[experimental][experimental]**.
    ///
    /// [vector_native_protobuf]: https://github.com/vectordotdev/vector/blob/master/lib/vector-core/proto/event.proto
    /// [experimental]: https://vector.dev/highlights/2022-03-31-native-event-codecs
    Native,

    /// Encodes an event in Vector’s [native JSON format][vector_native_json].
    ///
    /// This codec is **[experimental][experimental]**.
    ///
    /// [vector_native_json]: https://github.com/vectordotdev/vector/blob/master/lib/codecs/tests/data/native_encoding/schema.cue
    /// [experimental]: https://vector.dev/highlights/2022-03-31-native-event-codecs
    NativeJson,

    /// No encoding.
    ///
    /// This "encoding" simply uses the `message` field of a log event.
    ///
    /// Users should take care if they're modifying their log events (such as by using a `remap`
    /// transform, etc) and removing the message field while doing additional parsing on it, as this
    /// could lead to the encoding emitting empty strings for the given event.
    RawMessage,

    /// Plain text encoding.
    ///
    /// This "encoding" simply uses the `message` field of a log event. For metrics, it uses an
    /// encoding that resembles the Prometheus export format.
    ///
    /// Users should take care if they're modifying their log events (such as by using a `remap`
    /// transform, etc) and removing the message field while doing additional parsing on it, as this
    /// could lead to the encoding emitting empty strings for the given event.
    Text(
        /// Encoding options specific to the text serializer.
        TextSerializerConfig,
    ),

    /// Syslog encoding
    /// RFC 3164 and 5424 are supported
    Syslog (
        SyslogSerializerConfig,
    )
}

impl From<AvroSerializerConfig> for SerializerConfig {
    fn from(config: AvroSerializerConfig) -> Self {
        Self::Avro { avro: config.avro }
    }
}

impl From<GelfSerializerConfig> for SerializerConfig {
    fn from(_: GelfSerializerConfig) -> Self {
        Self::Gelf
    }
}

impl From<JsonSerializerConfig> for SerializerConfig {
    fn from(config: JsonSerializerConfig) -> Self {
        Self::Json(config)
    }
}

impl From<LogfmtSerializerConfig> for SerializerConfig {
    fn from(_: LogfmtSerializerConfig) -> Self {
        Self::Logfmt
    }
}

impl From<NativeSerializerConfig> for SerializerConfig {
    fn from(_: NativeSerializerConfig) -> Self {
        Self::Native
    }
}

impl From<NativeJsonSerializerConfig> for SerializerConfig {
    fn from(_: NativeJsonSerializerConfig) -> Self {
        Self::NativeJson
    }
}

impl From<RawMessageSerializerConfig> for SerializerConfig {
    fn from(_: RawMessageSerializerConfig) -> Self {
        Self::RawMessage
    }
}

impl From<TextSerializerConfig> for SerializerConfig {
    fn from(config: TextSerializerConfig) -> Self {
        Self::Text(config)
    }
}

impl From<SyslogSerializerConfig> for SerializerConfig {
    fn from(config: SyslogSerializerConfig) -> Self {
        Self::Syslog(config)
    }
}

impl SerializerConfig {
    /// Build the `Serializer` from this configuration.
    pub fn build(&self) -> Result<Serializer, Box<dyn std::error::Error + Send + Sync + 'static>> {
        match self {
            SerializerConfig::Avro { avro } => Ok(Serializer::Avro(
                AvroSerializerConfig::new(avro.schema.clone()).build()?,
            )),
            SerializerConfig::Gelf => Ok(Serializer::Gelf(GelfSerializerConfig::new().build())),
            SerializerConfig::Json(config) => Ok(Serializer::Json(config.build())),
            SerializerConfig::Logfmt => Ok(Serializer::Logfmt(LogfmtSerializerConfig.build())),
            SerializerConfig::Native => Ok(Serializer::Native(NativeSerializerConfig.build())),
            SerializerConfig::NativeJson => {
                Ok(Serializer::NativeJson(NativeJsonSerializerConfig.build()))
            }
            SerializerConfig::RawMessage => {
                Ok(Serializer::RawMessage(RawMessageSerializerConfig.build()))
            }
            SerializerConfig::Text(config) => Ok(Serializer::Text(config.build())),
            SerializerConfig::Syslog(config) => Ok(Serializer::Syslog(config.build())),
        }
    }

    /// Return an appropriate default framer for the given serializer.
    pub fn default_stream_framing(&self) -> FramingConfig {
        match self {
            // TODO: Technically, Avro messages are supposed to be framed[1] as a vector of
            // length-delimited buffers -- `len` as big-endian 32-bit unsigned integer, followed by
            // `len` bytes -- with a "zero-length buffer" to terminate the overall message... which
            // our length delimited framer obviously will not do.
            //
            // This is OK for now, because the Avro serializer is more ceremonial than anything
            // else, existing to curry serializer config options to Pulsar's native client, not to
            // actually serialize the bytes themselves... but we're still exposing this method and
            // we should do so accurately, even if practically it doesn't need to be.
            //
            // [1]: https://avro.apache.org/docs/1.11.1/specification/_print/#message-framing
            SerializerConfig::Avro { .. } | SerializerConfig::Native => {
                FramingConfig::LengthDelimited
            }
            SerializerConfig::Gelf
            | SerializerConfig::Json(_)
            | SerializerConfig::Logfmt
            | SerializerConfig::NativeJson
            | SerializerConfig::RawMessage
            | SerializerConfig::Text(_)
            | SerializerConfig::Syslog(_) => FramingConfig::NewlineDelimited,
        }
    }

    /// The data type of events that are accepted by this `Serializer`.
    pub fn input_type(&self) -> DataType {
        match self {
            SerializerConfig::Avro { avro } => {
                AvroSerializerConfig::new(avro.schema.clone()).input_type()
            }
            SerializerConfig::Gelf { .. } => GelfSerializerConfig::input_type(),
            SerializerConfig::Json(config) => config.input_type(),
            SerializerConfig::Logfmt => LogfmtSerializerConfig.input_type(),
            SerializerConfig::Native => NativeSerializerConfig.input_type(),
            SerializerConfig::NativeJson => NativeJsonSerializerConfig.input_type(),
            SerializerConfig::RawMessage => RawMessageSerializerConfig.input_type(),
            SerializerConfig::Text(config) => config.input_type(),
            SerializerConfig::Syslog(config) => config.input_type(),
        }
    }

    /// The schema required by the serializer.
    pub fn schema_requirement(&self) -> schema::Requirement {
        match self {
            SerializerConfig::Avro { avro } => {
                AvroSerializerConfig::new(avro.schema.clone()).schema_requirement()
            }
            SerializerConfig::Gelf { .. } => GelfSerializerConfig::schema_requirement(),
            SerializerConfig::Json(config) => config.schema_requirement(),
            SerializerConfig::Logfmt => LogfmtSerializerConfig.schema_requirement(),
            SerializerConfig::Native => NativeSerializerConfig.schema_requirement(),
            SerializerConfig::NativeJson => NativeJsonSerializerConfig.schema_requirement(),
            SerializerConfig::RawMessage => RawMessageSerializerConfig.schema_requirement(),
            SerializerConfig::Text(config) => config.schema_requirement(),
            SerializerConfig::Syslog(config) => config.schema_requirement(),
        }
    }
}

/// Serialize structured events as bytes.
#[derive(Debug, Clone)]
pub enum Serializer {
    /// Uses an `AvroSerializer` for serialization.
    Avro(AvroSerializer),
    /// Uses a `GelfSerializer` for serialization.
    Gelf(GelfSerializer),
    /// Uses a `JsonSerializer` for serialization.
    Json(JsonSerializer),
    /// Uses a `LogfmtSerializer` for serialization.
    Logfmt(LogfmtSerializer),
    /// Uses a `NativeSerializer` for serialization.
    Native(NativeSerializer),
    /// Uses a `NativeJsonSerializer` for serialization.
    NativeJson(NativeJsonSerializer),
    /// Uses a `RawMessageSerializer` for serialization.
    RawMessage(RawMessageSerializer),
    /// Uses a `TextSerializer` for serialization.
    Text(TextSerializer),
    /// Uses a `SyslogSerializer` for serialization.
    Syslog(SyslogSerializer),
}

impl Serializer {
    /// Check if the serializer supports encoding an event to JSON via `Serializer::to_json_value`.
    pub fn supports_json(&self) -> bool {
        match self {
            Serializer::Json(_) | Serializer::NativeJson(_) | Serializer::Gelf(_) => true,
            Serializer::Avro(_)
            | Serializer::Logfmt(_)
            | Serializer::Text(_)
            | Serializer::Native(_)
            | Serializer::RawMessage(_)
            | Serializer::Syslog(_) => false,
        }
    }

    /// Encode event and represent it as JSON value.
    ///
    /// # Panics
    ///
    /// Panics if the serializer does not support encoding to JSON. Call `Serializer::supports_json`
    /// if you need to determine the capability to encode to JSON at runtime.
    pub fn to_json_value(&self, event: Event) -> Result<serde_json::Value, vector_common::Error> {
        match self {
            Serializer::Gelf(serializer) => serializer.to_json_value(event),
            Serializer::Json(serializer) => serializer.to_json_value(event),
            Serializer::NativeJson(serializer) => serializer.to_json_value(event),
            Serializer::Avro(_)
            | Serializer::Logfmt(_)
            | Serializer::Text(_)
            | Serializer::Native(_)
            | Serializer::RawMessage(_)
            | Serializer::Syslog(_) => {
                panic!("Serializer does not support JSON")
            }
        }
    }
}

impl From<AvroSerializer> for Serializer {
    fn from(serializer: AvroSerializer) -> Self {
        Self::Avro(serializer)
    }
}

impl From<GelfSerializer> for Serializer {
    fn from(serializer: GelfSerializer) -> Self {
        Self::Gelf(serializer)
    }
}

impl From<JsonSerializer> for Serializer {
    fn from(serializer: JsonSerializer) -> Self {
        Self::Json(serializer)
    }
}

impl From<LogfmtSerializer> for Serializer {
    fn from(serializer: LogfmtSerializer) -> Self {
        Self::Logfmt(serializer)
    }
}

impl From<NativeSerializer> for Serializer {
    fn from(serializer: NativeSerializer) -> Self {
        Self::Native(serializer)
    }
}

impl From<NativeJsonSerializer> for Serializer {
    fn from(serializer: NativeJsonSerializer) -> Self {
        Self::NativeJson(serializer)
    }
}

impl From<RawMessageSerializer> for Serializer {
    fn from(serializer: RawMessageSerializer) -> Self {
        Self::RawMessage(serializer)
    }
}

impl From<TextSerializer> for Serializer {
    fn from(serializer: TextSerializer) -> Self {
        Self::Text(serializer)
    }
}

impl From<SyslogSerializer> for Serializer {
    fn from(serializer: SyslogSerializer) -> Self {
        Self::Syslog(serializer)
    }
}

impl tokio_util::codec::Encoder<Event> for Serializer {
    type Error = vector_common::Error;

    fn encode(&mut self, event: Event, buffer: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Serializer::Avro(serializer) => serializer.encode(event, buffer),
            Serializer::Gelf(serializer) => serializer.encode(event, buffer),
            Serializer::Json(serializer) => serializer.encode(event, buffer),
            Serializer::Logfmt(serializer) => serializer.encode(event, buffer),
            Serializer::Native(serializer) => serializer.encode(event, buffer),
            Serializer::NativeJson(serializer) => serializer.encode(event, buffer),
            Serializer::RawMessage(serializer) => serializer.encode(event, buffer),
            Serializer::Text(serializer) => serializer.encode(event, buffer),
            Serializer::Syslog(serializer) => serializer.encode(event, buffer),
        }
    }
}
