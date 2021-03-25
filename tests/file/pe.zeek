# @TEST-EXEC: ${ZEEK} -r ${TRACES}/ftp-pe.pcap %INPUT >out
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff pe.log
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: Test PE analyzer with an executable transferred over FTP.

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
	# TODO(bbannier): Since set order is not stable across zeek-3.x and
	# zeek-4.x we print the file header by hand. Once we drop support for zeek-3.x this function can be replaced by
	#
	#     print fmt("pe_file_header: %s", h);

	print fmt("pe_file_header: [machine=%s, ts=%s, sym_table_ptr=%s, num_syms=%s, optional_header_size=%s, characteristics={XXXXXXXX}]",
	          h$machine,
	          h$ts,
	          h$sym_table_ptr,
	          h$num_syms,
	          h$optional_header_size);

	const expected_characteristics = set(1, 2, 4, 8, 256);
	if ( h$characteristics != expected_characteristics )
		print fmt("ERROR: pe_file_header$characteristics does not match expectation (%s vs %s)",
		          h$characteristics,
		          expected_characteristics);
	}

event pe_optional_header(f: fa_file, h: PE::OptionalHeader)
	{
	print fmt("pe_optional_header: %s", h);
	}

event pe_section_header(f: fa_file, h: PE::SectionHeader)
	{
	print fmt("pe_section_header: %s", h);
	# TODO(bbannier): Since set order is not stable across zeek-3.x and
	# zeek-4.x we print the file header by hand so we can canonify
	# `characteristics`. Once we drop support for zeek-3.x this function
	# can be replaced by
	#
	#     print fmt("pe_section_header: %s", h);

	print fmt("pe_section_header: [name=%s, virtual_size=%s, virtual_addr=%s, size_of_raw_data=%s, ptr_to_raw_data=%s, ptr_to_relocs=%s, ptr_to_line_nums=%s, num_of_relocs=%s, num_of_line_nums=%s, characteristics={XXXXXXXX}]",
	          h$name,
	          h$virtual_size,
	          h$virtual_addr,
	          h$size_of_raw_data,
	          h$ptr_to_raw_data,
	          h$ptr_to_relocs,
	          h$ptr_to_line_nums,
	          h$num_of_relocs,
	          h$num_of_line_nums);

	# NOTE: The parsing of `characteristics` is tested above in
	# `pe_file_header` and not repeated here as our test payload contains
	# multiple, different section headers.
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
