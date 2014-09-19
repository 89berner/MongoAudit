MongoAudit
==========

Auditing tool for Mongo

There are 3 parts for this tool:

1) The Agent, which must run on a Mongo instance

2) The Repeater, which can run in any instance and must be reachable by the Agent

3) The Mongosniff auditing tool, which sniffs the Mongo traffic and outputs the operations

4) The Parser, which would parse the data in Mongosniff in a format that would be usefull

[OPTIONAL] 5) A logstash agent to upload logs to ElasticSearch

