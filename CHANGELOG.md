# 2.0.6
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
# 2.0.5
  - New dependency requirements for logstash-core for the 5.0 release
## 2.0.4
 - Fixed: Fields without values could claim the next field + value under certain circumstances. Reported in #22

## 2.0.3
 - fixed fixed short circuit expressions, some optimizations, added specs, PR #20
 - fixed event field assignment, PR #21

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

# 1.1.0
 - Add new features as support spaces between key and value_split,
   support brackets and recursive option.
