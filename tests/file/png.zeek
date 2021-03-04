# @TEST-EXEC: ${ZEEK} -B file_analysis -r ${TRACES}/pipelined-requests.trace %INPUT
# @TEST-EXEC: ${ZEEK} -NN > zeek
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff png.log
#
# @TEST-DOC: Test TFTP analyzer with write request trace.

@load spicy-analyzers/file/png
