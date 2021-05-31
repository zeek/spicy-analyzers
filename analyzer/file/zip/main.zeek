module ZIP;

export {
	type File: record {
		## True if from global directory header, false if from local file header
		global_: bool;
		## File ID associated with content analysis of this file. Only available for local
		## headers where file content has been further processed.
		fid: string &optional;
		## Name of file
		filename: string;
		## Timestamp of file
		time_: time;
		## Comment associated with file.
		comment: string;
		## Compression type
		compression: ZIP::CompressionMethod;
		## True if encrypted
		encrypted: bool;
	};
}

redef record Files::Info += {
	## File timestamp
	ftime: time &optional &log;
};

# Maps FIDs to their meta data.
global archives: table[string] of ZIP::File;

event ZIP::file(f: fa_file, meta: ZIP::File) {
	if ( meta?$fid )
		archives[meta$fid] = meta;
	}

event file_state_remove(f: fa_file) {
	if ( f$id !in archives )
		return;

	local meta = archives[f$id];
	f$info$filename = meta$filename;
	f$info$ftime = meta$time_;
	delete archives[f$id];
}
