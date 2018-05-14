# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"

# This filter helps automatically parse messages (or specific event fields)
# which are of the `foo=bar` variety.
#
# For example, if you have a log message which contains `ip=1.2.3.4
# error=REFUSED`, you can parse those automatically by configuring:
# [source,ruby]
#     filter {
#       kv { }
#     }
#
# The above will result in a message of `ip=1.2.3.4 error=REFUSED` having
# the fields:
#
# * `ip: 1.2.3.4`
# * `error: REFUSED`
#
# This is great for postfix, iptables, and other types of logs that
# tend towards `key=value` syntax.
#
# You can configure any arbitrary strings to split your data on,
# in case your data is not structured using `=` signs and whitespace.
# For example, this filter can also be used to parse query parameters like
# `foo=bar&baz=fizz` by setting the `field_split` parameter to `&`.
class LogStash::Filters::KV < LogStash::Filters::Base
  config_name "kv"

  # Constants used for transform check
  TRANSFORM_LOWERCASE_KEY = "lowercase"
  TRANSFORM_UPPERCASE_KEY = "uppercase"
  TRANSFORM_CAPITALIZE_KEY = "capitalize"

  # A string of characters to trim from the value. This is useful if your
  # values are wrapped in brackets or are terminated with commas (like postfix
  # logs).
  #
  # These characters form a regex character class and thus you must escape special regex
  # characters like `[` or `]` using `\`.
  #
  # Only leading and trailing characters are trimed from the value.
  #
  # For example, to trim `<`, `>`, `[`, `]` and `,` characters from values:
  # [source,ruby]
  #     filter {
  #       kv {
  #         trim_value => "<>\[\],"
  #       }
  #     }
  config :trim_value, :validate => :string

  # A string of characters to trim from the key. This is useful if your
  # keys are wrapped in brackets or start with space.
  #
  # These characters form a regex character class and thus you must escape special regex
  # characters like `[` or `]` using `\`.
  #
  # Only leading and trailing characters are trimed from the key.
  #
  # For example, to trim `<` `>` `[` `]` and `,` characters from keys:
  # [source,ruby]
  #     filter {
  #       kv {
  #         trim_key => "<>\[\],"
  #       }
  #     }
  config :trim_key, :validate => :string

  # A string of characters to remove from the value.
  #
  # These characters form a regex character class and thus you must escape special regex
  # characters like `[` or `]` using `\`.
  #
  # Contrary to trim option, all characters are removed from the value, whatever their position.
  #
  # For example, to remove `<`, `>`, `[`, `]` and `,` characters from values:
  # [source,ruby]
  #     filter {
  #       kv {
  #         remove_char_value => "<>\[\],"
  #       }
  #     }
  config :remove_char_value, :validate => :string

  # A string of characters to remove from the key.
  #
  # These characters form a regex character class and thus you must escape special regex
  # characters like `[` or `]` using `\`.
  #
  # Contrary to trim option, all characters are removed from the key, whatever their position.
  #
  # For example, to remove `<` `>` `[` `]` and `,` characters from keys:
  # [source,ruby]
  #     filter {
  #       kv {
  #         remove_char_key => "<>\[\],"
  #       }
  #     }
  config :remove_char_key, :validate => :string

  # Transform values to lower case, upper case or capitals.
  #
  # For example, to capitalize all values:
  # [source,ruby]
  #     filter {
  #       kv {
  #         transform_value => "capitalize"
  #       }
  #     }
  config :transform_value, :validate => [TRANSFORM_LOWERCASE_KEY, TRANSFORM_UPPERCASE_KEY, TRANSFORM_CAPITALIZE_KEY]

  # Transform keys to lower case, upper case or capitals.
  #
  # For example, to lowercase all keys:
  # [source,ruby]
  #     filter {
  #       kv {
  #         transform_key => "lowercase"
  #       }
  #     }
  config :transform_key, :validate => [TRANSFORM_LOWERCASE_KEY, TRANSFORM_UPPERCASE_KEY, TRANSFORM_CAPITALIZE_KEY]

  # A string of characters to use as single-character field delimiters for parsing out key-value pairs.
  #
  # These characters form a regex character class and thus you must escape special regex
  # characters like `[` or `]` using `\`.
  #
  # #### Example with URL Query Strings
  #
  # For example, to split out the args from a url query string such as
  # `?pin=12345~0&d=123&e=foo@bar.com&oq=bobo&ss=12345`:
  # [source,ruby]
  #     filter {
  #       kv {
  #         field_split => "&?"
  #       }
  #     }
  #
  # The above splits on both `&` and `?` characters, giving you the following
  # fields:
  #
  # * `pin: 12345~0`
  # * `d: 123`
  # * `e: foo@bar.com`
  # * `oq: bobo`
  # * `ss: 12345`
  config :field_split, :validate => :string, :default => ' '

  # A regex expression to use as field delimiter for parsing out key-value pairs.
  # Useful to define multi-character field delimiters.
  # Setting the field_split_pattern options will take precedence over the field_split option.
  #
  # Note that you should avoid using captured groups in your regex and you should be
  # cautious with lookaheads or lookbehinds and positional anchors.
  #
  # For example, to split fields on a repetition of one or more colons
  # `k1=v1:k2=v2::k3=v3:::k4=v4`:
  # [source,ruby]
  #     filter { kv { field_split_pattern => ":+" } }
  #
  # To split fields on a regex character that need escaping like the plus sign
  # `k1=v1++k2=v2++k3=v3++k4=v4`:
  # [source,ruby]
  #     filter { kv { field_split_pattern => "\\+\\+" } }
  config :field_split_pattern, :validate => :string

  # A non-empty string of characters to use as single-character value delimiters for parsing out key-value pairs.
  #
  # These characters form a regex character class and thus you must escape special regex
  # characters like `[` or `]` using `\`.
  #
  # For example, to identify key-values such as
  # `key1:value1 key2:value2`:
  # [source,ruby]
  #     filter { kv { value_split => ":" } }
  config :value_split, :validate => :string, :default => '='

  # A regex expression to use as value delimiter for parsing out key-value pairs.
  # Useful to define multi-character value delimiters.
  # Setting the value_split_pattern options will take precedence over the value_split option.
  #
  # Note that you should avoid using captured groups in your regex and you should be
  # cautious with lookaheads or lookbehinds and positional anchors.
  #
  # See field_split_pattern for examples.
  config :value_split_pattern, :validate => :string

  # A string to prepend to all of the extracted keys.
  #
  # For example, to prepend arg_ to all keys:
  # [source,ruby]
  #     filter { kv { prefix => "arg_" } }
  config :prefix, :validate => :string, :default => ''

  # The field to perform `key=value` searching on
  #
  # For example, to process the `not_the_message` field:
  # [source,ruby]
  #     filter { kv { source => "not_the_message" } }
  config :source, :validate => :string, :default => "message"

  # The name of the container to put all of the key-value pairs into.
  #
  # If this setting is omitted, fields will be written to the root of the
  # event, as individual fields.
  #
  # For example, to place all keys into the event field kv:
  # [source,ruby]
  #     filter { kv { target => "kv" } }
  config :target, :validate => :string

  # An array specifying the parsed keys which should be added to the event.
  # By default all keys will be added.
  #
  # For example, consider a source like `Hey, from=<abc>, to=def foo=bar`.
  # To include `from` and `to`, but exclude the `foo` key, you could use this configuration:
  # [source,ruby]
  #     filter {
  #       kv {
  #         include_keys => [ "from", "to" ]
  #       }
  #     }
  config :include_keys, :validate => :array, :default => []

  # An array specifying the parsed keys which should not be added to the event.
  # By default no keys will be excluded.
  #
  # For example, consider a source like `Hey, from=<abc>, to=def foo=bar`.
  # To exclude `from` and `to`, but retain the `foo` key, you could use this configuration:
  # [source,ruby]
  #     filter {
  #       kv {
  #         exclude_keys => [ "from", "to" ]
  #       }
  #     }
  config :exclude_keys, :validate => :array, :default => []

  # A hash specifying the default keys and their values which should be added to the event
  # in case these keys do not exist in the source field being parsed.
  # [source,ruby]
  #     filter {
  #       kv {
  #         default_keys => [ "from", "logstash@example.com",
  #                          "to", "default@dev.null" ]
  #       }
  #     }
  config :default_keys, :validate => :hash, :default => {}

  # A bool option for removing duplicate key/value pairs. When set to false, only
  # one unique key/value pair will be preserved.
  #
  # For example, consider a source like `from=me from=me`. `[from]` will map to
  # an Array with two elements: `["me", "me"]`. To only keep unique key/value pairs,
  # you could use this configuration:
  # [source,ruby]
  #     filter {
  #       kv {
  #         allow_duplicate_values => false
  #       }
  #     }
  config :allow_duplicate_values, :validate => :boolean, :default => true

  # A boolean specifying whether to treat square brackets, angle brackets,
  # and parentheses as value "wrappers" that should be removed from the value.
  # [source,ruby]
  #     filter {
  #       kv {
  #         include_brackets => true
  #       }
  #     }
  #
  # For example, the result of this line:
  # `bracketsone=(hello world) bracketstwo=[hello world] bracketsthree=<hello world>`
  #
  # will be:
  #
  # * bracketsone: hello world
  # * bracketstwo: hello world
  # * bracketsthree: hello world
  #
  # instead of:
  #
  # * bracketsone: (hello
  # * bracketstwo: [hello
  # * bracketsthree: <hello
  #
  config :include_brackets, :validate => :boolean, :default => true

  # A boolean specifying whether to drill down into values
  # and recursively get more key-value pairs from it.
  # The extra key-value pairs will be stored as subkeys of the root key.
  #
  # Default is not to recursive values.
  # [source,ruby]
  #     filter {
  #       kv {
  #         recursive => "true"
  #       }
  #     }
  #
  config :recursive, :validate => :boolean, :default => false

  def register
    if @value_split.empty?
      raise LogStash::ConfigurationError, I18n.t(
        "logstash.runner.configuration.invalid_plugin_register",
        :plugin => "filter",
        :type => "kv",
        :error => "Configuration option 'value_split' must be a non-empty string"
      )
    end

    if @field_split_pattern && @field_split_pattern.empty?
      raise LogStash::ConfigurationError, I18n.t(
          "logstash.runner.configuration.invalid_plugin_register",
          :plugin => "filter",
          :type => "kv",
          :error => "Configuration option 'field_split_pattern' must be a non-empty string"
      )
    end

    if @value_split_pattern && @value_split_pattern.empty?
      raise LogStash::ConfigurationError, I18n.t(
          "logstash.runner.configuration.invalid_plugin_register",
          :plugin => "filter",
          :type => "kv",
          :error => "Configuration option 'value_split_pattern' must be a non-empty string"
      )
    end

    @trim_value_re = Regexp.new("^[#{@trim_value}]+|[#{@trim_value}]+$") if @trim_value
    @trim_key_re = Regexp.new("^[#{@trim_key}]+|[#{@trim_key}]+$") if @trim_key

    @remove_char_value_re = Regexp.new("[#{@remove_char_value}]") if @remove_char_value
    @remove_char_key_re = Regexp.new("[#{@remove_char_key}]") if @remove_char_key

    field_split = Regexp::compile(@field_split_pattern || /[#{@field_split}]/)
    value_split = Regexp::compile(@value_split_pattern || /[#{@value_split}]/)

    optional_whitespace = /\s*/
    eof = /$/

    value_pattern = begin
      # each component expression within value_pattern _must_ capture exactly once.
      value_patterns = []

      value_patterns << quoted_capture(%q(")) # quoted double
      value_patterns << quoted_capture(%q(')) # quoted single
      if @include_brackets
        value_patterns << quoted_capture('(', ')') # bracketed paren
        value_patterns << quoted_capture('[', ']') # bracketed square
        value_patterns << quoted_capture('<', '>') # bracketed angle
      end

      # an unquoted value is a _captured_ sequence of characters or escaped spaces before a `field_split` or EOF.
      value_patterns << /((?:\\ |.)*?)(?=#{Regexp::union(field_split, eof)})/

      Regexp.union(*value_patterns)
    end


    # a key is a _captured_ sequence of characters or escaped spaces before optional whitespace
    # and followed by either a `value_split`, a `field_split`, or EOF.
    key_pattern = /((?:\\ |.)+?)(?=#{optional_whitespace}#{Regexp::union(value_split, field_split, eof)})/

    @scan_re = /#{field_split}?#{key_pattern}#{optional_whitespace}(?:#{value_split}#{optional_whitespace}#{value_pattern})?(?=#{Regexp::union(field_split, eof)})/
    @value_split_re = value_split

    @logger.debug? && @logger.debug("KV scan regex", :regex => @scan_re.inspect)
  end

  def filter(event)
    kv = Hash.new
    value = event.get(@source)

    case value
    when nil
      # Nothing to do
    when String
      kv = parse(value, event, kv)
    when Array
      value.each { |v| kv = parse(v, event, kv) }
    else
      @logger.warn("kv filter has no support for this type of data", :type => value.class, :value => value)
    end

    # Add default key-values for missing keys
    kv = @default_keys.merge(kv)

    return if kv.empty?

    if @target
      @logger.debug? && @logger.debug("Overwriting existing target field", :target => @target)
      event.set(@target, kv)
    else
      kv.each{|k, v| event.set(k, v)}
    end

    filter_matched(event)
  end

  private

  def has_value_splitter?(s)
    s =~ @value_split_re
  end

  # Helper function for generating single-capture `Regexp` that, when matching a string bound by the given quotes
  # or brackets, will capture the content that is between the quotes or brackets.
  #
  # @api private
  # @param quote_sequence [String] a character sequence that begins a quoted expression
  # @param close_quote_sequence [String] a character sequence that ends a quoted expression; (default: quote_sequence)
  # @return [Regexp] with a single capture group representing content that is between the given quotes
  def quoted_capture(quote_sequence, close_quote_sequence=quote_sequence)
    fail('quote_sequence must be non-empty!') if quote_sequence.nil? || quote_sequence.empty?
    fail('close_quote_sequence must be non-empty!') if close_quote_sequence.nil? || close_quote_sequence.empty?

    open_pattern = /#{Regexp.quote(quote_sequence)}/
    close_pattern = /#{Regexp.quote(close_quote_sequence)}/

    # matches a sequence of zero or more characters are _not_ the `close_quote_sequence`
    quoted_value_pattern = /[^#{Regexp.quote(close_quote_sequence)}]*/

    /#{open_pattern}(#{quoted_value_pattern})#{close_pattern}/
  end

  def transform(text, method)
    case method
    when TRANSFORM_LOWERCASE_KEY
      return text.downcase
    when TRANSFORM_UPPERCASE_KEY
      return text.upcase
    when TRANSFORM_CAPITALIZE_KEY
      return text.capitalize
    end
  end

  def parse(text, event, kv_keys)
    # short circuit parsing if the text does not contain the @value_split
    return kv_keys unless has_value_splitter?(text)

    # Interpret dynamic keys for @include_keys and @exclude_keys
    include_keys = @include_keys.map{|key| event.sprintf(key)}
    exclude_keys = @exclude_keys.map{|key| event.sprintf(key)}

    text.scan(@scan_re) do |key, *value_candidates|
      value = value_candidates.compact.first
      next if value.nil? || value.empty?

      key = @trim_key ? key.gsub(@trim_key_re, "") : key
      key = @remove_char_key ? key.gsub(@remove_char_key_re, "") : key
      key = @transform_key ? transform(key, @transform_key) : key

      # Bail out as per the values of include_keys and exclude_keys
      next if not include_keys.empty? and not include_keys.include?(key)
      # next unless include_keys.include?(key)
      next if exclude_keys.include?(key)

      key = event.sprintf(@prefix) + key

      value = @trim_value ? value.gsub(@trim_value_re, "") : value
      value = @remove_char_value ? value.gsub(@remove_char_value_re, "") : value
      value = @transform_value ? transform(value, @transform_value) : value

      # Bail out if inserting duplicate value in key mapping when unique_values
      # option is set to true.
      next if not @allow_duplicate_values and kv_keys.has_key?(key) and kv_keys[key].include?(value)

      # recursively get more kv pairs from the value
      if @recursive
        innerKv = parse(value, event, {})
        value = innerKv unless innerKv.empty?
      end

      if kv_keys.has_key?(key)
        if kv_keys[key].is_a?(Array)
          kv_keys[key].push(value)
        else
          kv_keys[key] = [kv_keys[key], value]
        end
      else
        kv_keys[key] = value
      end
    end

    return kv_keys
  end
end
