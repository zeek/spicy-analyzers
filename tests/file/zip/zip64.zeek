# @TEST-EXEC: zeek -Cr ${TRACES}/zip/zip64.pcap %INPUT
# @TEST-EXEC: cat weird.log | zeek-cut name
# @TEST-EXEC: btest-diff .stdout
#
# @TEST-DOC: Feed a ZIP64 archive into the ZIP, which is currently not supported but will reported

@load spicy-analyzers/zip

event ZIP::file(f: fa_file, meta: ZIP::File) {
	print meta;
}

event ZIP::end_of_directory(f: fa_file, comment: string) {
	print comment;
}
