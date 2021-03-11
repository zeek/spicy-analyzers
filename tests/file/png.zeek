# @TEST-EXEC: ${ZEEK} -B file_analysis -r ${TRACES}/png.pcap %INPUT
# @TEST-EXEC: ${ZEEK} -NN > zeek
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff png.log
#
# @TEST-DOC: Test PNG analyzer with an image inside a small trace.

@load spicy-analyzers/file/png
