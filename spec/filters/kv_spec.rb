# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/filters/kv"

# Logstash starts JRuby with a special flag to ensure that regexp's are
# executed in an interruptible fashion.
require 'java'
if java.lang.System.getProperty("jruby.regexp.interruptible") != "true"
  fail("Java must be started with `-Djruby.regexp.interruptible=true`")
end

describe LogStash::Filters::KV do

  describe "defaults" do
    # The logstash config goes here.
    # At this time, only filters are supported.
    config <<-CONFIG
      filter {
        kv { }
      }
    CONFIG

    sample "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world' bracketsone=(hello world) bracketstwo=[hello world] bracketsthree=<hello world>" do
      insist { subject.get("hello") } == "world"
      insist { subject.get("foo") } == "bar"
      insist { subject.get("baz") } == "fizz"
      insist { subject.get("doublequoted") } == "hello world"
      insist { subject.get("singlequoted") } == "hello world"
      insist { subject.get("bracketsone") } == "hello world"
      insist { subject.get("bracketstwo") } == "hello world"
      insist { subject.get("bracketsthree") } == "hello world"
    end
  end

  describe  "test transforming keys to uppercase and values to lowercase" do
    config <<-CONFIG
      filter {
        kv {
          transform_key => "uppercase"
          transform_value => "lowercase"
        }
      }
    CONFIG

    sample "hello = world Foo =Bar BAZ= FIZZ doublequoteD = \"hellO worlD\" Singlequoted= 'Hello World' brAckets =(hello World)" do
      insist { subject.get("HELLO") } == "world"
      insist { subject.get("FOO") } == "bar"
      insist { subject.get("BAZ") } == "fizz"
      insist { subject.get("DOUBLEQUOTED") } == "hello world"
      insist { subject.get("SINGLEQUOTED") } == "hello world"
      insist { subject.get("BRACKETS") } == "hello world"
    end
  end

  describe 'whitespace => strict' do
    config <<-CONFIG
      filter {
        kv {
          whitespace => strict
        }
      }
    CONFIG

    context 'unquoted values' do
      sample "IN=eth0 OUT= MAC=0f:5f:5e:aa:d3:a2:21:ff:09:00:0f:e1:c8:17 SRC=192.168.0.1" do
        insist { subject.get('IN') } == 'eth0'
        insist { subject.get('OUT') } == nil # when whitespace is strict, OUT is empty and thus uncaptured.
        insist { subject.get('MAC') } == '0f:5f:5e:aa:d3:a2:21:ff:09:00:0f:e1:c8:17'
        insist { subject.get('SRC') } == '192.168.0.1'
      end
    end

    context 'mixed quotations' do
      sample 'hello=world goodbye=cruel\\ world empty_quoted="" quoted="value1" empty_unquoted= unquoted=value2 empty_bracketed=[] bracketed=[value3] cake=delicious' do
        insist { subject.get('hello') } == 'world'
        insist { subject.get('goodbye') } == 'cruel\\ world'
        insist { subject.get('empty_quoted') } == nil
        insist { subject.get('quoted') } == 'value1'
        insist { subject.get('empty_unquoted') } == nil
        insist { subject.get('unquoted') } == 'value2'
        insist { subject.get('empty_bracketed') } == nil
        insist { subject.get('bracketed') } == 'value3'
        insist { subject.get('cake') } == 'delicious'
      end
    end

    context 'when given sloppy input, it extracts only the unambiguous bits' do
      sample "hello = world foo =bar baz= fizz whitespace=none doublequoted = \"hello world\" singlequoted= 'hello world' brackets =(hello world) strict=true" do
        insist { subject.get('whitespace') } == 'none'
        insist { subject.get('strict') } == 'true'

        insist { subject.to_hash.keys.sort } == %w(@timestamp @version message strict whitespace)
      end
    end
  end

  describe  "test transforming keys to lowercase and values to uppercase" do
    config <<-CONFIG
      filter {
        kv {
          transform_key => "lowercase"
          transform_value => "uppercase"
        }
      }
    CONFIG

    sample "Hello = World fOo =bar baz= FIZZ DOUBLEQUOTED = \"hellO worlD\" singlequoted= 'hEllo wOrld' brackets =(HELLO world)" do
      insist { subject.get("hello") } == "WORLD"
      insist { subject.get("foo") } == "BAR"
      insist { subject.get("baz") } == "FIZZ"
      insist { subject.get("doublequoted") } == "HELLO WORLD"
      insist { subject.get("singlequoted") } == "HELLO WORLD"
      insist { subject.get("brackets") } == "HELLO WORLD"
    end
  end

  describe  "test transforming keys and values to capitals" do
    config <<-CONFIG
      filter {
        kv {
          transform_key => "capitalize"
          transform_value => "capitalize"
        }
      }
    CONFIG

    sample "Hello = World fOo =bar baz= FIZZ DOUBLEQUOTED = \"hellO worlD\" singlequoted= 'hEllo wOrld' brackets =(HELLO world)" do
      insist { subject.get("Hello") } == "World"
      insist { subject.get("Foo") } == "Bar"
      insist { subject.get("Baz") } == "Fizz"
      insist { subject.get("Doublequoted") } == "Hello world"
      insist { subject.get("Singlequoted") } == "Hello world"
      insist { subject.get("Brackets") } == "Hello world"
    end
  end

  describe  "test spaces attached to the field_split" do
    config <<-CONFIG
      filter {
        kv { }
      }
    CONFIG

    sample "hello = world foo =bar baz= fizz doublequoted = \"hello world\" singlequoted= 'hello world' brackets =(hello world)" do
      insist { subject.get("hello") } == "world"
      insist { subject.get("foo") } == "bar"
      insist { subject.get("baz") } == "fizz"
      insist { subject.get("doublequoted") } == "hello world"
      insist { subject.get("singlequoted") } == "hello world"
      insist { subject.get("brackets") } == "hello world"
    end
  end

   describe "LOGSTASH-624: allow escaped space in key or value " do
    config <<-CONFIG
      filter {
        kv { value_split => ':' }
      }
    CONFIG

    sample 'IKE:=Quick\ Mode\ completion IKE\ IDs:=subnet:\ x.x.x.x\ (mask=\ 255.255.255.254)\ and\ host:\ y.y.y.y' do
      insist { subject.get("IKE") } == '=Quick\ Mode\ completion'
      insist { subject.get('IKE\ IDs') } == '=subnet:\ x.x.x.x\ (mask=\ 255.255.255.254)\ and\ host:\ y.y.y.y'
    end
  end

  describe "test value_split" do
    context "using an alternate splitter" do
      config <<-CONFIG
        filter {
          kv { value_split => ':' }
        }
      CONFIG

      sample "hello:=world foo:bar baz=:fizz doublequoted:\"hello world\" singlequoted:'hello world' brackets:(hello world)" do
        insist { subject.get("hello") } == "=world"
        insist { subject.get("foo") } == "bar"
        insist { subject.get("baz=") } == "fizz"
        insist { subject.get("doublequoted") } == "hello world"
        insist { subject.get("singlequoted") } == "hello world"
        insist { subject.get("brackets") } == "hello world"
      end
    end
  end

  # these specs are quite implementation specific by testing on the private method
  # has_value_splitter?  - this is what I figured would help fixing the short circuit
  # broken code that was previously in place
  describe "short circuit" do
    subject do
      plugin = LogStash::Filters::KV.new(options)
      plugin.register
      plugin
    end
    let(:data) { {"message" => message} }
    let(:event) { LogStash::Event.new(data) }

    context "plain message" do
      let(:options) { {} }

      context "without splitter" do
        let(:message) { "foo:bar" }
        it "should short circuit" do
          expect(subject.send(:has_value_splitter?, message)).to be_falsey
          expect(subject).to receive(:has_value_splitter?).with(message).once.and_return(false)
          subject.filter(event)
        end
      end

      context "with splitter" do
        let(:message) { "foo=bar" }
        it "should not short circuit" do
          expect(subject.send(:has_value_splitter?, message)).to be_truthy
          expect(subject).to receive(:has_value_splitter?).with(message).once.and_return(true)
          subject.filter(event)
        end
      end
    end

    context "recursive message" do
      context "without inner splitter" do
        let(:inner) { "bar" }
        let(:message) { "foo=#{inner}" }
        let(:options) { {"recursive" => "true"} }

        it "should extract kv" do
          subject.filter(event)
          expect(event.get("foo")).to eq(inner)
        end

        it "should short circuit" do
          expect(subject.send(:has_value_splitter?, message)).to be_truthy
          expect(subject.send(:has_value_splitter?, inner)).to be_falsey
          expect(subject).to receive(:has_value_splitter?).with(message).once.and_return(true)
          expect(subject).to receive(:has_value_splitter?).with(inner).once.and_return(false)
          subject.filter(event)
        end
      end

      context "with inner splitter" do
        let(:foo_val) { "1" }
        let(:baz_val) { "2" }
        let(:inner) { "baz=#{baz_val}" }
        let(:message) { "foo=#{foo_val} bar=(#{inner})" } # foo=1 bar=(baz=2)
        let(:options) { {"recursive" => "true"} }

        it "should extract kv" do
          subject.filter(event)
          expect(event.get("foo")).to eq(foo_val)
          expect(event.get("[bar][baz]")).to eq(baz_val)
        end

        it "should short circuit" do
          expect(subject.send(:has_value_splitter?, message)).to be_truthy
          expect(subject.send(:has_value_splitter?, foo_val)).to be_falsey

          expect(subject.send(:has_value_splitter?, inner)).to be_truthy
          expect(subject.send(:has_value_splitter?, baz_val)).to be_falsey

          expect(subject).to receive(:has_value_splitter?).with(message).once.and_return(true)
          expect(subject).to receive(:has_value_splitter?).with(foo_val).once.and_return(false)

          expect(subject).to receive(:has_value_splitter?).with(inner).once.and_return(true)
          expect(subject).to receive(:has_value_splitter?).with(baz_val).once.and_return(false)

          subject.filter(event)
        end
      end
    end
  end

  describe "test field_split" do
    config <<-CONFIG
      filter {
        kv { field_split => '?&' }
      }
    CONFIG

    sample "?hello=world&foo=bar&baz=fizz&doublequoted=\"hello world\"&singlequoted='hello world'&ignoreme&foo12=bar12" do
      insist { subject.get("hello") } == "world"
      insist { subject.get("foo") } == "bar"
      insist { subject.get("baz") } == "fizz"
      insist { subject.get("doublequoted") } == "hello world"
      insist { subject.get("singlequoted") } == "hello world"
      insist { subject.get("foo12") } == "bar12"
    end
  end

  describe "test include_brackets is false" do
    config <<-CONFIG
      filter {
        kv { include_brackets => "false" }
      }
    CONFIG

    sample "bracketsone=(hello world) bracketstwo=[hello world]" do
      insist { subject.get("bracketsone") } == "(hello"
      insist { subject.get("bracketstwo") } == "[hello"
    end
  end

  describe "test recursive" do
    config <<-CONFIG
      filter {
        kv {
          recursive => 'true'
        }
      }
    CONFIG

    sample 'IKE="Quick Mode completion" IKE\ IDs = (subnet= x.x.x.x mask= 255.255.255.254 and host=y.y.y.y)' do
      insist { subject.get("IKE") } == 'Quick Mode completion'
      insist { subject.get('IKE\ IDs')['subnet'] } == 'x.x.x.x'
      insist { subject.get('IKE\ IDs')['mask'] } == '255.255.255.254'
      insist { subject.get('IKE\ IDs')['host'] } == 'y.y.y.y'
    end
  end

  describe  "delimited fields should override space default (reported by LOGSTASH-733)" do
    config <<-CONFIG
      filter {
        kv { field_split => "|" }
      }
    CONFIG

    sample "field1=test|field2=another test|field3=test3" do
      insist { subject.get("field1") } == "test"
      insist { subject.get("field2") } == "another test"
      insist { subject.get("field3") } == "test3"
    end
  end

  describe "test prefix" do
    config <<-CONFIG
      filter {
        kv { prefix => '__' }
      }
    CONFIG

    sample "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world'" do
      insist { subject.get("__hello") } == "world"
      insist { subject.get("__foo") } == "bar"
      insist { subject.get("__baz") } == "fizz"
      insist { subject.get("__doublequoted") } == "hello world"
      insist { subject.get("__singlequoted") } == "hello world"
    end

  end

  describe "speed test", :performance => true do
    count = 10000 + rand(3000)
    config <<-CONFIG
      input {
        generator {
          count => #{count}
          type => foo
          message => "hello=world bar='baz fizzle'"
        }
      }

      filter {
        kv { }
      }

      output  {
        null { }
      }
    CONFIG

    start = Time.now
    agent do
      duration = (Time.now - start)
      puts "filters/kv rate: #{"%02.0f/sec" % (count / duration)}, elapsed: #{duration}s"
    end
  end

  describe "add_tag" do
    context "should activate when successful" do
      config <<-CONFIG
        filter {
          kv { add_tag => "hello" }
        }
      CONFIG

      sample "hello=world" do
        insist { subject.get("hello") } == "world"
        insist { subject.get("tags") }.include?("hello")
      end
    end
    context "should not activate when failing" do
      config <<-CONFIG
        filter {
          kv { add_tag => "hello" }
        }
      CONFIG

      sample "this is not key value" do
        insist { subject.get("tags") }.nil?
      end
    end
  end

  describe "add_field" do
    context "should activate when successful" do
      config <<-CONFIG
        filter {
          kv { add_field => [ "whoa", "fancypants" ] }
        }
      CONFIG

      sample "hello=world" do
        insist { subject.get("hello") } == "world"
        insist { subject.get("whoa") } == "fancypants"
      end
    end

    context "should not activate when failing" do
      config <<-CONFIG
        filter {
          kv { add_tag => "hello" }
        }
      CONFIG

      sample "this is not key value" do
        reject { subject.get("whoa") } == "fancypants"
      end
    end
  end

  #New tests
  describe "test target" do
    config <<-CONFIG
      filter {
        kv { target => 'kv' }
      }
    CONFIG

    sample "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world'" do
      insist { subject.get("kv")["hello"] } == "world"
      insist { subject.get("kv")["foo"] } == "bar"
      insist { subject.get("kv")["baz"] } == "fizz"
      insist { subject.get("kv")["doublequoted"] } == "hello world"
      insist { subject.get("kv")["singlequoted"] } == "hello world"
      insist {subject.get("kv").count } == 5
    end

  end

  describe "test empty target" do
    config <<-CONFIG
      filter {
        kv { target => 'kv' }
      }
    CONFIG

    sample "hello:world:foo:bar:baz:fizz" do
      insist { subject.get("kv") } == nil
    end
  end

  describe "test data from specific sub source" do
    config <<-CONFIG
      filter {
        kv {
          source => "data"
        }
      }
    CONFIG
    sample("data" => "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world'") do
      insist { subject.get("hello") } == "world"
      insist { subject.get("foo") } == "bar"
      insist { subject.get("baz") } == "fizz"
      insist { subject.get("doublequoted") } == "hello world"
      insist { subject.get("singlequoted") } == "hello world"
    end
  end

  describe "test data from specific top source" do
    config <<-CONFIG
      filter {
        kv {
          source => "@data"
        }
      }
    CONFIG
    sample({"@data" => "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world'"}) do
      insist { subject.get("hello") } == "world"
      insist { subject.get("foo") } == "bar"
      insist { subject.get("baz") } == "fizz"
      insist { subject.get("doublequoted") } == "hello world"
      insist { subject.get("singlequoted") } == "hello world"
    end
  end

  describe 'field_split_pattern with literal backslashes' do
    config <<-CONFIG
      filter {
        kv {
          source => headers
          field_split_pattern => "\\\\r\\\\n"
          value_split_pattern => ": "
          whitespace => strict
          target => headerskv
        }
      }
    CONFIG

    sample({"headers"=>"Host: foo.com\\r\\nUser-Agent: Qwerty/1.2.3 (www.qwerty.org)\\r\\nContent-Type: text/xml; charset=utf-8\\r\\nAccept: */*\\r\\nAccept-Encoding: gzip, deflate\\r\\nContent-Length: 123\\r\\nX-UUID: 0:15713435944943992\\r\\n\\r\\n"}) do
      insist { subject.get("[headerskv][Host]") } == "foo.com"
      insist { subject.get("[headerskv][User-Agent]") } == "Qwerty/1.2.3 (www.qwerty.org)"
      insist { subject.get("[headerskv][Content-Type]") } == "text/xml; charset=utf-8"
      insist { subject.get("[headerskv][Accept]") } == "*/*"
      insist { subject.get("[headerskv][Accept-Encoding]") } == "gzip, deflate"
      insist { subject.get("[headerskv][Content-Length]") } == "123"
      insist { subject.get("[headerskv][X-UUID]") } == "0:15713435944943992"
    end
  end

  describe "test data from specific sub source and target" do
    config <<-CONFIG
      filter {
        kv {
          source => "data"
          target => "kv"
        }
      }
    CONFIG
    sample("data" => "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world'") do
      insist { subject.get("kv")["hello"] } == "world"
      insist { subject.get("kv")["foo"] } == "bar"
      insist { subject.get("kv")["baz"] } == "fizz"
      insist { subject.get("kv")["doublequoted"] } == "hello world"
      insist { subject.get("kv")["singlequoted"] } == "hello world"
      insist { subject.get("kv").count } == 5
    end
  end

  describe "test data from nil sub source, should not issue a warning" do
    config <<-CONFIG
      filter {
        kv {
          source => "non-exisiting-field"
          target => "kv"
        }
      }
    CONFIG
    sample "" do
      insist { subject.get("non-exisiting-field") } == nil
      insist { subject.get("kv") } == nil
    end
  end

  describe "test include_keys" do
    config <<-CONFIG
      filter {
        kv {
          include_keys => [ "foo", "singlequoted" ]
        }
      }
    CONFIG

    sample "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world'" do
      insist { subject.get("foo") } == "bar"
      insist { subject.get("singlequoted") } == "hello world"
    end
  end

  describe "test exclude_keys" do
    config <<-CONFIG
      filter {
        kv {
          exclude_keys => [ "foo", "singlequoted" ]
        }
      }
    CONFIG

    sample "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world'" do
      insist { subject.get("hello") } == "world"
      insist { subject.get("baz") } == "fizz"
      insist { subject.get("doublequoted") } == "hello world"
    end
  end

  describe "test include_keys with prefix" do
    config <<-CONFIG
      filter {
        kv {
          include_keys => [ "foo", "singlequoted" ]
          prefix       => "__"
        }
      }
    CONFIG

    sample "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world'" do
      insist { subject.get("__foo") } == "bar"
      insist { subject.get("__singlequoted") } == "hello world"
    end
  end

  describe "test exclude_keys with prefix" do
    config <<-CONFIG
      filter {
        kv {
          exclude_keys => [ "foo", "singlequoted" ]
          prefix       => "__"
        }
      }
    CONFIG

    sample "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world'" do
      insist { subject.get("__hello") } == "world"
      insist { subject.get("__baz") } == "fizz"
      insist { subject.get("__doublequoted") } == "hello world"
    end
  end

  describe "test include_keys with dynamic key" do
    config <<-CONFIG
      filter {
        kv {
          source => "data"
          include_keys => [ "%{key}"]
        }
      }
    CONFIG

    sample({"data" => "foo=bar baz=fizz", "key" => "foo"}) do
      insist { subject.get("foo") } == "bar"
      insist { subject.get("baz") } == nil
    end
  end

  describe "test exclude_keys with dynamic key" do
    config <<-CONFIG
      filter {
        kv {
          source => "data"
          exclude_keys => [ "%{key}"]
        }
      }
    CONFIG

    sample({"data" => "foo=bar baz=fizz", "key" => "foo"}) do
      insist { subject.get("foo") } == nil
      insist { subject.get("baz") } == "fizz"
    end
  end

  describe "test include_keys and exclude_keys" do
    config <<-CONFIG
      filter {
        kv {
          # This should exclude everything as a result of both settings.
          include_keys => [ "foo", "singlequoted" ]
          exclude_keys => [ "foo", "singlequoted" ]
        }
      }
    CONFIG

    sample "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world'" do
      %w(hello foo baz doublequoted singlequoted).each do |field|
        reject { subject }.include?(field)
      end
    end
  end

  describe "test default_keys" do
    config <<-CONFIG
      filter {
        kv {
          default_keys => [ "foo", "xxx",
                            "goo", "yyy" ]
        }
      }
    CONFIG

    sample "hello=world foo=bar baz=fizz doublequoted=\"hello world\" singlequoted='hello world'" do
      insist { subject.get("hello") } == "world"
      insist { subject.get("foo") } == "bar"
      insist { subject.get("goo") } == "yyy"
      insist { subject.get("baz") } == "fizz"
      insist { subject.get("doublequoted") } == "hello world"
      insist { subject.get("singlequoted") } == "hello world"
    end
  end

  describe "overwriting a string field (often the source)" do
    config <<-CONFIG
      filter {
        kv {
          source => "happy"
          target => "happy"
        }
      }
    CONFIG

    sample("happy" => "foo=bar baz=fizz") do
      insist { subject.get("[happy][foo]") } == "bar"
      insist { subject.get("[happy][baz]") } == "fizz"
    end

  end

  describe "Removing duplicate key/value pairs" do
    config <<-CONFIG
      filter {
        kv {
          field_split => "&"
          source => "source"
          allow_duplicate_values => false
        }
      }
    CONFIG

    sample("source" => "foo=bar&foo=yeah&foo=yeah") do
      insist { subject.get("[foo]") } == ["bar", "yeah"]
    end
  end

  describe "Allowing empty values" do
    config <<-CONFIG
      filter {
        kv {
          field_split => " "
          source => "source"
          allow_empty_values => true
          whitespace => strict
        }
      }
    CONFIG

    sample("source" => "present=one empty= emptyquoted='' present=two emptybracketed=[] endofinput=") do
      insist { subject.get('[present]') } == ['one','two']
      insist { subject.get('[empty]') } == ''
      insist { subject.get('[emptyquoted]') } == ''
      insist { subject.get('[emptybracketed]') } == ''
      insist { subject.get('[endofinput]') } == ''
    end
  end

  describe "Allow duplicate key/value pairs by default" do
    config <<-CONFIG
      filter {
        kv {
          field_split => "&"
          source => "source"
        }
      }
    CONFIG

    sample("source" => "foo=bar&foo=yeah&foo=yeah") do
      insist { subject.get("[foo]") } == ["bar", "yeah", "yeah"]
    end
  end

  describe "keys without values (reported in #22)" do
    subject do
      plugin = LogStash::Filters::KV.new(options)
      plugin.register
      plugin
    end

    let(:f1) { "AccountStatus" }
    let(:v1) { "4" }
    let(:f2) { "AdditionalInformation" }
    let(:f3) { "Code" }
    let(:f4) { "HttpStatusCode" }
    let(:f5) { "IsSuccess" }
    let(:v5) { "True" }
    let(:f6) { "Message" }

    let(:message) { "#{f1}: #{v1}\r\n#{f2}\r\n\r\n#{f3}: \r\n#{f4}: \r\n#{f5}: #{v5}\r\n#{f6}: \r\n" }
    let(:data) { {"message" => message} }
    let(:event) { LogStash::Event.new(data) }
    let(:options) {
      {
        "field_split" => "\r\n",
        "value_split" => " ",
        "trim_key" => ":"
      }
    }

    context "key and splitters with no value" do
      it "should ignore the incomplete key/value pairs" do
        subject.filter(event)
        expect(event.get(f1)).to eq(v1)
        expect(event.get(f5)).to eq(v5)
        expect(event.include?(f2)).to be false
        expect(event.include?(f3)).to be false
        expect(event.include?(f4)).to be false
        expect(event.include?(f6)).to be false
      end
    end
  end

  describe "trim_key/trim_value options : trim only leading and trailing spaces in keys/values (reported in #10)" do
    subject do
      plugin = LogStash::Filters::KV.new(options)
      plugin.register
      plugin
    end

    let(:message) { "key1= value1 with spaces | key2 with spaces =value2" }
    let(:data) { {"message" => message} }
    let(:event) { LogStash::Event.new(data) }
    let(:options) {
      {
        "field_split" => "\|",
        "value_split" => "=",
        "trim_value" => " ",
        "trim_key" => " "
      }
    }

    context "key and value with leading, trailing and middle spaces" do
      it "should trim only leading and trailing spaces" do
        subject.filter(event)
        expect(event.get("key1")).to eq("value1 with spaces")
        expect(event.get("key2 with spaces")).to eq("value2")
      end
    end
  end

  describe "trim_key/trim_value options : trim multiple matching characters from either end" do
    subject do
      plugin = LogStash::Filters::KV.new(options)
      plugin.register
      plugin
    end

    let(:data) { {"message" => message} }
    let(:event) { LogStash::Event.new(data) }


    context 'repeated same-character sequence' do
      let(:message) { "key1=  value1 with spaces    |  key2 with spaces  =value2" }
      let(:options) {
        {
            "field_split" => "|",
            "value_split" => "=",
            "trim_value" => " ",
            "trim_key" => " "
        }
      }

      it 'trims all the right bits' do
        subject.filter(event)
        expect(event.get('key1')).to eq('value1 with spaces')
        expect(event.get('key2 with spaces')).to eq('value2')
      end
    end

    context 'multi-character sequence' do
      let(:message) { "to=<foo@example.com>, orig_to=<bar@example.com>, %+relay=mail.example.com[private/dovecot-lmtp], delay=2.2, delays=1.9/0.01/0.01/0.21, dsn=2.0.0, status=sent (250 2.0.0 <foo@example.com> YERDHejiRSXFDSdfUXTV Saved) " }
      let(:options) {
        {
            "field_split" => " ",
            "value_split" => "=",
            "trim_value" => "<>,",
            "trim_key" => "%+"
        }
      }

      it 'trims all the right bits' do
        subject.filter(event)
        expect(event.get('to')).to eq('foo@example.com')
        expect(event.get('orig_to')).to eq('bar@example.com')
        expect(event.get('relay')).to eq('mail.example.com[private/dovecot-lmtp]')
        expect(event.get('delay')).to eq('2.2')
        expect(event.get('delays')).to eq('1.9/0.01/0.01/0.21')
        expect(event.get('dsn')).to eq('2.0.0')
        expect(event.get('status')).to eq('sent')
      end
    end
  end

  describe "remove_char_key/remove_char_value options : remove all characters in keys/values whatever their position" do
    subject do
      plugin = LogStash::Filters::KV.new(options)
      plugin.register
      plugin
    end
  
    let(:message) { "key1= value1 with spaces | key2 with spaces =value2" }
    let(:data) { {"message" => message} }
    let(:event) { LogStash::Event.new(data) }
    let(:options) {
      {
        "field_split" => "\|",
        "value_split" => "=",
        "remove_char_value" => " ",
        "remove_char_key" => " "
      }
    }
  
    context "key and value with leading, trailing and middle spaces" do
      it "should remove all spaces" do
        subject.filter(event)
        expect(event.get("key1")).to eq("value1withspaces")
        expect(event.get("key2withspaces")).to eq("value2")
      end
    end
  end

  describe "an empty value_split option should be reported" do
    config <<-CONFIG
      filter {
        kv {
          value_split => ""
        }
      }
    CONFIG

    sample("message" => "random message") do
      insist { subject }.raises(LogStash::ConfigurationError)
    end
  end
end

describe "multi character splitting" do
  subject do
    plugin = LogStash::Filters::KV.new(options)
    plugin.register
    plugin
  end

  let(:data) { {"message" => message} }
  let(:event) { LogStash::Event.new(data) }

  shared_examples "parsing all fields and values" do
    it "parses all fields and values" do
      subject.filter(event)
      expect(event.get("hello")).to eq("world")
      expect(event.get("foo")).to eq("bar")
      expect(event.get("baz")).to eq("fizz")
      expect(event.get("doublequoted")).to eq("hello world")
      expect(event.get("singlequoted")).to eq("hello world")
      expect(event.get("bracketsone")).to eq("hello world")
      expect(event.get("bracketstwo")).to eq("hello world")
      expect(event.get("bracketsthree")).to eq("hello world")
    end
  end

  context "empty value_split_pattern" do
    let(:options) { { "value_split_pattern" => "" } }
    it "should raise ConfigurationError" do
      expect{subject}.to raise_error(LogStash::ConfigurationError)
    end
  end

  context "empty field_split_pattern" do
    let(:options) { { "field_split_pattern" => "" } }
    it "should raise ConfigurationError" do
      expect{subject}.to raise_error(LogStash::ConfigurationError)
    end
  end

  context "single split" do
    let(:message) { "hello:world foo:bar baz:fizz doublequoted:\"hello world\" singlequoted:'hello world' bracketsone:(hello world) bracketstwo:[hello world] bracketsthree:<hello world>" }
    let(:options) {
      {
          "field_split" => " ",
          "value_split" => ":",
      }
    }
    it_behaves_like "parsing all fields and values"
  end

  context "value split multi" do
    let(:message) { "hello::world foo::bar baz::fizz doublequoted::\"hello world\" singlequoted::'hello world' bracketsone::(hello world) bracketstwo::[hello world] bracketsthree::<hello world>" }
    let(:options) {
      {
          "field_split" => " ",
          "value_split_pattern" => "::",
      }
    }
    it_behaves_like "parsing all fields and values"
  end

  context 'multi-char field split pattern with value that begins quoted and contains more unquoted' do
    let(:message) { 'foo=bar!!!!!baz="quoted stuff" and more unquoted!!!!!msg="fully-quoted with a part! of the separator"!!!!!blip="this!!!!!is it"!!!!!empty=""!!!!!non-empty="foo"' }
    let(:options) {
      {
          "field_split_pattern" => "!!!!!"
      }
    }
    it 'gets the right bits' do
      subject.filter(event)
      expect(event.get("foo")).to eq('bar')
      expect(event.get("baz")).to eq('"quoted stuff" and more unquoted')
      expect(event.get("msg")).to eq('fully-quoted with a part! of the separator')
      expect(event.get("blip")).to eq('this!!!!!is it')
      expect(event.get("empty")).to be_nil
      expect(event.get("non-empty")).to eq('foo')
    end
  end

  context 'standard field split pattern with value that begins quoted and contains more unquoted' do
    let(:message) { 'foo=bar baz="quoted stuff" and more unquoted msg="some fully-quoted message " empty="" non-empty="foo"' }
    let(:options) {
      {
      }
    }
    it 'gets the right bits' do
      subject.filter(event)
      expect(event.get("foo")).to eq('bar')
      expect(event.get("baz")).to eq('quoted stuff') # NOTE: outside the quotes is truncated because field split pattern wins.
      expect(event.get("msg")).to eq('some fully-quoted message ')
      expect(event.get("empty")).to be_nil
      expect(event.get("non-empty")).to eq('foo')
    end
  end

  context "field and value split multi" do
    let(:message) { "hello::world__foo::bar__baz::fizz__doublequoted::\"hello world\"__singlequoted::'hello world'__bracketsone::(hello world)__bracketstwo::[hello world]__bracketsthree::<hello world>" }
    let(:options) {
      {
          "field_split_pattern" => "__",
          "value_split_pattern" => "::",
      }
    }
    it_behaves_like "parsing all fields and values"
  end

  context "field and value split multi with regex" do
    let(:message) { "hello:world_foo::bar__baz:::fizz___doublequoted:::\"hello world\"____singlequoted:::::'hello world'____bracketsone:::(hello world)__bracketstwo:[hello world]_bracketsthree::::::<hello world>" }
    let(:options) {
      {
          "field_split_pattern" => "_+",
          "value_split_pattern" => ":+",
      }
    }
    it_behaves_like "parsing all fields and values"
  end

  context "field and value split multi using singe char" do
    let(:message) { "hello:world foo:bar baz:fizz doublequoted:\"hello world\" singlequoted:'hello world' bracketsone:(hello world) bracketstwo:[hello world] bracketsthree:<hello world>" }
    let(:options) {
      {
          "field_split_pattern" => " ",
          "value_split_pattern" => ":",
      }
    }
    it_behaves_like "parsing all fields and values"
  end

  context "field and value split multi using escaping" do
    let(:message) { "hello++world??foo++bar??baz++fizz??doublequoted++\"hello world\"??singlequoted++'hello world'??bracketsone++(hello world)??bracketstwo++[hello world]??bracketsthree++<hello world>" }
    let(:options) {
      {
          "field_split_pattern" => "\\?\\?",
          "value_split_pattern" => "\\+\\+",
      }
    }
    it_behaves_like "parsing all fields and values"
  end

  context "example from @guyboertje in #15" do
    let(:message) { 'key1: val1; key2: val2; key3:  https://site/?g={......"...;  CLR  rv:11.0)"..}; key4: val4;' }
    let(:options) {
      {
          "field_split_pattern" => ";\s*(?=key.+?:)|;$",
          "value_split_pattern" => ":\s+",
      }
    }

    it "parses all fields and values" do
      subject.filter(event)

      expect(event.get("key1")).to eq("val1")
      expect(event.get("key2")).to eq("val2")
      expect(event.get("key3")).to eq("https://site/?g={......\"...;  CLR  rv:11.0)\"..}")
      expect(event.get("key4")).to eq("val4")
    end
  end

  describe "handles empty values" do
    let(:message) { 'a=1|b=|c=3' }

    shared_examples "parse empty values" do
      it "splits correctly upon empty value" do
        subject.filter(event)

        expect(event.get("a")).to eq("1")
        expect(event.get("b")).to be_nil
        expect(event.get("c")).to eq("3")
      end
    end

    context "using char class splitters" do
      let(:options) {
        {
            "field_split" => "|",
            "value_split" => "=",
        }
      }
      it_behaves_like "parse empty values"
    end

    context "using pattern splitters" do
      let(:options) {
        {
            "field_split_pattern" => '\|',
            "value_split_pattern" => "=",
        }
      }
      it_behaves_like "parse empty values"
    end
  end
end

context 'runtime errors' do

  let(:options) { {} }
  let(:plugin) do
    LogStash::Filters::KV.new(options).instance_exec { register; self }
  end

  let(:data) { {"message" => message} }
  let(:event) { LogStash::Event.new(data) }
  let(:message) { "foo=bar hello=world" }


  before(:each) do
    expect(plugin).to receive(:parse) { fail('intentional') }
  end

  context 'when a runtime error is raised' do
    it 'does not cascade the exception to crash the plugin' do
      plugin.filter(event)
    end
    it 'tags the event with "_kv_filter_error"' do
      plugin.filter(event)
      expect(event.get('tags')).to_not be_nil
      expect(event.get('tags')).to include('_kv_filter_error')
    end
    it 'logs an informative message' do
      logger_double = double('Logger').as_null_object
      expect(plugin).to receive(:logger).and_return(logger_double).at_least(:once)
      expect(logger_double).to receive(:warn).with('Exception while parsing KV', anything)

      plugin.filter(event)
    end
    context 'when a custom tag is defined' do
      let(:options) { super().merge("tag_on_failure" => "KV-ERROR")}
      it 'tags the event with the custom tag' do
        plugin.filter(event)
        expect(event.get('tags')).to_not be_nil
        expect(event.get('tags')).to include('KV-ERROR')
        expect(event.get('tags')).to_not include('_kv_filter_error')
      end
    end
    context 'when multiple custom tags are defined' do
      let(:options) { super().merge("tag_on_failure" => ["kv_FAIL_one", "_kv_fail_TWO"])}
      it 'tags the event with the custom tag' do
        plugin.filter(event)
        expect(event.get('tags')).to_not be_nil
        expect(event.get('tags')).to include('kv_FAIL_one')
        expect(event.get('tags')).to include('_kv_fail_TWO')
        expect(event.get('tags')).to_not include('_kv_filter_error')
      end
    end
  end
end

# This group intentionally uses patterns that are vulnerable to pathological inputs to test timeouts.
#
# patterns of the form `/(?:x+x+)+y/` are vulnerable to inputs that have long sequences matching `/x/`
# that are _not_ followed by a sequence matching `/y/`.
context 'timeouts' do
  let(:options) do
    {
        "value_split_pattern" => "(?:=+=+)+:"
    }
  end
  subject(:plugin) do
    LogStash::Filters::KV.new(options).instance_exec { register; self }
  end

  let(:data) { {"message" => message} }
  let(:event) { LogStash::Event.new(data) }
  let(:message) { "foo=bar hello=world" }

  after(:each) { plugin.close }

  # since we are dealing with potentially-pathological specs, ensure specs fail in a timely
  # manner if they block for longer than `spec_blocking_threshold_seconds`.
  let(:spec_blocking_threshold_seconds) { 10 }
  around(:each) do |example|
    begin
      blocking_exception_class = Class.new(::Exception) # avoid RuntimeError, which is handled in KV#filter
      Timeout.timeout(spec_blocking_threshold_seconds, blocking_exception_class, &example)
    rescue blocking_exception_class
      fail('execution blocked')
    end
  end

  context 'when timeouts are enabled' do
    let(:options) { super().merge("timeout_millis" => 250) }
    let(:spec_blocking_threshold_seconds) { 3 }

    context 'when given a pathological input' do
      let(:message) { "foo========:bar baz================================================bingo" }

      it 'tags the event' do
        plugin.filter(event)

        expect(event.get('tags')).to be_a_kind_of(Enumerable)
        expect(event.get('tags')).to include('_kv_filter_timeout')
      end

      context 'when given a custom `tag_on_timeout`' do
        let(:options) { super().merge('tag_on_timeout' => 'BADKV') }

        it 'tags the event with the custom tag' do
          plugin.filter(event)

          expect(event.get('tags')).to be_a_kind_of(Enumerable)
          expect(event.get('tags')).to include('BADKV')
        end
      end

      context 'when default_keys are provided' do
        let(:options) { super().merge("default_keys" => {"default" => "key"})}

        it 'does not populate default keys' do
          plugin.filter(event)

          expect(event).to_not include('default')
        end
      end
      context 'when filter_matched hooks are provided' do
        let(:options) { super().merge("add_field" => {"kv" => "success"})}

        it 'does not call filter_matched hooks' do
          plugin.filter(event)

          expect(event).to_not include('kv')
        end
      end
    end

    context 'when given a non-pathological input' do
      let(:message) { "foo==:bar baz==:bingo" }

      it 'extracts the k/v' do
        plugin.filter(event)

        expect(event.get('foo')).to eq('bar')
        expect(event.get('baz')).to eq('bingo')
      end
    end
  end

  context 'when timeouts are explicitly disabled' do
    let(:options) { super().merge("timeout_millis" => 0) }

    context 'when given a pathological input' do
      let(:message) { "foo========:bar baz================================================================bingo"}

      it 'blocks for at least 3 seconds' do
        blocking_exception_class = Class.new(::Exception) # avoid RuntimeError, which is handled in KV#filter
        expect do
          Timeout.timeout(3, blocking_exception_class) do
            plugin.filter(event)
          end
        end.to raise_exception(blocking_exception_class)
      end
    end

    context 'when given a non-pathological input' do
      let(:message) { "foo==:bar baz==:bingo" }

      it 'extracts the k/v' do
        plugin.filter(event)

        expect(event.get('foo')).to eq('bar')
        expect(event.get('baz')).to eq('bingo')
      end
    end
  end
end
