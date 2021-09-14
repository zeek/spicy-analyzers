module PE;

export {

	type ExportName: record {
		rva:  count;
		name: string &optional;
	};

	type ExportAddress: record {
		rva:       count;
		forwarder: string &optional;
	};

	type ExportTable: record {
		flags:               count;
		timestamp:           time;
		major_version:       count;
		minor_version:       count;
		dll_name_rva:        count;
		ordinal_base:        count;
		address_table_count: count;
		name_table_count:    count;
		address_table_rva:   count;
		name_table_rva:      count;
		ordinal_table_rva:   count;
		dll:                 string &optional;
		addresses:           vector of ExportAddress &optional;
		names:               vector of ExportName &optional;
		ordinals:            vector of count &optional;
	};

	type Import: record {
		hint_name_rva: count &optional;
		hint:          count &optional;
		name:          string &optional;
		ordinal:       count &optional;
	};

	type ImportTableEntry: record {
		import_lookup_table_rva:  count;
		timestamp:                time;
		forwarder_chain:          count;
		dll_rva:                  count;
		import_address_table_rva: count;
		dll:                      string &optional;
		imports:                  vector of Import &optional;
	};

	type ImportTable: record {
		entries: vector of ImportTableEntry;
	};

}

module Files;

# This is a way of bypassing Zeek's automatic PE analysis using its own PE
# analyzer.  It helps prevent duplicate events on Zeek 4.0 and before, where
# there's no API to disable file analyzers and so Spicy .evt can't rely
# on the 'replaces' setting to help substitute for Zeek's builtin PE analyzer.
# This wouldn't prevent someone from manually using Zeek's builtin PE
# via Files::add_analyzer(), but it work work for most cases (also, when using
# 'replaces' someone could still end up bypassing via Files::enable_analyzer()
# and somehow end up getting duplicates if they're motivated enough).
event zeek_init() &priority=-10
	{
	local pe_tag = Files::ANALYZER_PE;

	if ( pe_tag !in Files::mime_types )
		return;

	for ( mt in Files::mime_types[pe_tag] )
		delete Files::mime_type_to_analyzers[mt][pe_tag];

	delete Files::mime_types[pe_tag];
	}
