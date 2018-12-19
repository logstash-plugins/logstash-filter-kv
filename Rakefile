@files=[]

task :default do
  system("rake -T")
end

require "logstash/devutils/rake"

task :vendor do
  system("./gradlew vendor")
end
