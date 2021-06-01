module Facefish_Rootkit;

export {
	const command = {
		[0x200] = "KeyEx1",
		[0x201] = "KeyEx2",
		[0x202] = "KeyEx3",
		[0x300] = "Report_Info",
		[0x301] = "Collect_Info",
		[0x302] = "Shell",
		[0x305] = "Registration",
		[0x310] = "Run_Command",
		[0x311] = "Return_Command",
		[0x312] = "Recollect_Info",
	} &default = function(n: count): string { return fmt("unknown-command-%d", n); };
}