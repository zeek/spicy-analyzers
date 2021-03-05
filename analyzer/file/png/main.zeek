module PNG;

export {

	redef enum Log::ID += { LOG };

	const PNG_COLOUR_TYPE_GREYSCALE = 0;
	const PNG_COLOUR_TYPE_TRUECOLOUR = 2;
	const PNG_COLOUR_TYPE_INDEXED_COLOUR = 3;
	const PNG_COLOUR_TYPE_GREYSCALE_WITH_ALPHA = 4;
	const PNG_COLOUR_TYPE_TRUECOLOUR_WITH_ALPHA = 6;

	## Mapping between numeric codes and string values for colour types
	const colour_types: table[count] of string = {
		[PNG_COLOUR_TYPE_GREYSCALE] = "greyscale",
		[PNG_COLOUR_TYPE_TRUECOLOUR] = "truecolour",
		[PNG_COLOUR_TYPE_INDEXED_COLOUR] = "indexed-colour",
		[PNG_COLOUR_TYPE_GREYSCALE_WITH_ALPHA] = "greyscale with alpha",
		[PNG_COLOUR_TYPE_TRUECOLOUR_WITH_ALPHA] = "truecolour with alpha"
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

	type Info: record {
		## Current timestamp
		ts:             time             &log;
		## File ID of this PNG
		id:             string           &log;
		## Chunk types in the PNG, in the order in which they appeared
		chunks:         vector of string &log &optional;
		## Image width in pixels
		width:          count            &log &optional;
		## height in pixels
		height:         count            &log &optional;
		## Image colour type
		colour_type:    string           &log &optional;
		## Image bit depth
		bit_depth:      count            &log &optional;
		## Flag is set to true if image is interlaced
		interlaced:     bool             &log &optional;
		## Last modification time
		last_modified:  time             &log &optional;
	};

	global log_png: event(rec: Info);

	global set_file: hook(f: fa_file);

	type PaletteEntry: record {
		red: count;
		green: count;
		blue: count;
	};
}

redef record fa_file += {
	png: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_png, $path="png"]);
	}

hook set_file(f: fa_file) &priority=5
	{
	if ( ! f?$png )
		f$png = PNG::Info($ts=network_time(), $id=f$id);
	}

event PNG::chunk(f: fa_file, chunk_type: string, length: count)
	{
	hook set_file(f);

	if ( ! f$png?$chunks )
		f$png$chunks = vector();

	f$png$chunks += chunk_type;
	}

event PNG::image_header(f: fa_file, width: count, height: count, bit_depth: count, colour_type: count, compression_method: count, filter_method: count, interlace_method: count)
	{
	hook set_file(f);

	f$png$width = width;
	f$png$height = height;
	f$png$bit_depth = bit_depth;
	f$png$interlaced = interlace_method != 0;
	f$png$colour_type = colour_types[colour_type];
	}

event PNG::last_modification_time(f: fa_file, year: count, month: count, day: count, hour: count, minute: count, second: count)
	{
	hook set_file(f);

	f$png$last_modified = strptime("%Y-%m-%d-%H-%M-%S", fmt("%04d-%02d-%02d-%02d-%02d-%02d", year, month, day, hour, minute, second));
	}

event file_state_remove(f: fa_file) &priority=-5
	{
	if ( ! f?$png )
		return;

	Log::write(LOG, f$png);
	}
