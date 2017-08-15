## 4.0.2
  - Fix some documentation issues

## 4.0.0
  - breaking: trim and trimkey options are renamed to trim_value and trim_key
  - bugfix: trim_value and trim_key options now remove only leading and trailing characters (#10)
  - feature: new options remove_char_value and remove_char_key to remove all characters from keys/values whatever their position

## 3.1.1
  - internal,deps: Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 3.1.0
  - Adds :transform_value and :transform_key options to lowercase/upcase or capitalize all keys/values
## 3.0.1
 - internal: Republish all the gems under jruby.

## 3.0.0
 - internal,deps: Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141

## 2.0.7
 - feature: With include_brackets enabled, angle brackets (\< and \>) are treated the same as square brackets and parentheses, making it easy to parse strings like "a=\<b\> c=\<d\>".
 - feature: An empty value_split option value now gives a useful error message.

## 2.0.6
 - internal,deps: Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash

## 2.0.5
 - internal,deps: New dependency requirements for logstash-core for the 5.0 release

## 2.0.4
 - bugfix: Fields without values could claim the next field + value under certain circumstances. Reported in #22

## 2.0.3
 - bugfix: fixed short circuit expressions, some optimizations, added specs, PR #20
 - bugfix: fixed event field assignment, PR #21

## 2.0.0
 - internal: Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - internal,deps: Dependency on logstash-core update to 2.0

## 1.1.0
 - feature: support spaces between key and value_split,
   support brackets and recursive option.
