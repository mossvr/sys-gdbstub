

all: sysmodule/sys-gdbstub.nsp applet/gdbstub.nro out

dist: sys-gdbstub.zip

applet/gdbstub.nro: .FORCE
	$(MAKE) -C applet

sysmodule/sys-gdbstub.nsp: .FORCE
	$(MAKE) -C sysmodule

out: sysmodule/sys-gdbstub.nsp
	@rm -rf out
	@mkdir -p out
	@mkdir -p out/atmosphere/contents/4200000000474442
	@mkdir -p out/atmosphere/contents/4200000000474442/flags
	@cp sysmodule/sys-gdbstub.nsp out/atmosphere/contents/4200000000474442/exefs.nsp
	@cp sysmodule/toolbox.json out/atmosphere/contents/4200000000474442/toolbox.json
	@touch out/atmosphere/contents/4200000000474442/flags/boot2.flag

sys-gdbstub.zip: out
	@echo creating $@
	@cd $<; zip -r ../$@ ./*; cd ../;

.FORCE:

.PHONY: all dist