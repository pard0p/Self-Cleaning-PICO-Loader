#
# Self-Cleaning PICO Loader build spec
#

x64:
	load "bin/loader.x64.o"
		make pic +gofirst +optimize

		dfr "resolve" "ror13"
		mergelib "libs/libtcg/libtcg.x64.zip"

		push $OBJECT
			make object +optimize
			export
			link "my_data"

		disassemble "out.txt"

	load "pic_end.o"
		preplen
		link "pic_end"

		export