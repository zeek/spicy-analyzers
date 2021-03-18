# @TEST-EXEC: ${ZEEK} -r ${TRACES}/ftp-pe.pcap %INPUT >out
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff pe.log
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: Test PE analyzer with an executable transferred over FTP.
#
# @TEST-KNOWN-FAILURE: This test currently fails, output is not matching baseline

@load spicy-analyzers/file/pe

event pe_dos_header(f: fa_file, h: PE::DOSHeader)
	{
	print fmt("pe_dos_header: %s", h);
	}

event pe_dos_code(f: fa_file, code: string)
	{
	print fmt("pe_dos_code size: %s", |code|);
	}

event pe_file_header(f: fa_file, h: PE::FileHeader)
	{
	print fmt("pe_file_header: %s", h);
	}

event pe_optional_header(f: fa_file, h: PE::OptionalHeader)
	{
	print fmt("pe_optional_header: %s", h);
	}

event pe_section_header(f: fa_file, h: PE::SectionHeader)
	{
	print fmt("pe_section_header: %s", h);
	}

function print_imports(imports: vector of PE::Import)
	{
	for ( i in imports )
		{
		local imp = imports[i];
		if ( imp?$hint_name_rva )
			print fmt("    Import: [%s][%s] %s",
			          imp$hint_name_rva,
			          imp?$hint ? cat(imp$hint) : "<nil>",
			          imp?$name ? imp$name : "<nil>"
			          );
		else
			print fmt("    Import: [ordinal %s]", imp$ordinal);
		}
	}

event pe_import_table(f: fa_file, it: PE::ImportTable)
	{
	# print fmt("Import Table for %s:", f$id);

	for ( i in it$entries )
		{
		local e = it$entries[i];
		print fmt("  Import DLL: [%s] %s", e$dll_rva, e?$dll ? e$dll : "nil");
		if ( e?$imports ) print_imports(e$imports);
		}
	}
