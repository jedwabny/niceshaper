BINDIR?=/usr/local/bin

bindir=$(DESTDIR)$(BINDIR)
cfgdir=$(DESTDIR)/etc/niceshaper
vardir=$(DESTDIR)/var/lib/niceshaper
docdir=$(DESTDIR)/usr/share/doc/niceshaper

conffile=config.conf
clasfile=class.conf

TARGET=niceshaper

all:
	@echo "###########" 
	@echo "# Compiling"
	@echo "###"
	$(MAKE) -C src 
	mv src/$(TARGET) $(TARGET)

install: all
	@echo "####################"
	@echo "Installing documents"
	@echo "###"
	install -d $(cfgdir) $(docdir)
	install -d $(docdir)/editors $(docdir)/editors/mc $(docdir)/editors/vim 
	install -d $(docdir)/examples 
	install -d $(docdir)/html $(docdir)/html/en $(docdir)/html/pl
	install -d -m 750 $(vardir)
	install -m 644 ./etc/niceshaper/$(conffile) $(docdir)/examples/
	install -m 644 ./etc/niceshaper/$(clasfile) $(docdir)/examples/
	install -m 644 ./editors/mc/* $(docdir)/editors/mc/
	install -m 644 ./editors/vim/* $(docdir)/editors/vim/
	install -m 644 ./docs/htb.png $(docdir)/html/
	install -m 644 ./docs/mrtg.png $(docdir)/html/
	install -m 644 ./docs/ns.css $(docdir)/html/
	install -m 644 ./docs/en/* $(docdir)/html/en/
	install -m 644 ./docs/pl/* $(docdir)/html/pl/
	@echo "#################"
	@echo "Installing binary"
	@echo "###"
	install -D -m 755 $(TARGET) $(bindir)/$(TARGET)
	@echo "########################"
	@echo "Installing configuration"
	@echo "###"
	test -e $(cfgdir)/$(conffile) && install -m 644 ./etc/niceshaper/$(conffile) $(cfgdir)/$(conffile)-dist || install -m 644 ./etc/niceshaper/$(conffile) $(cfgdir)/$(conffile)
	test -e $(cfgdir)/$(clasfile) && install -m 644 ./etc/niceshaper/$(clasfile) $(cfgdir)/$(clasfile)-dist || install -m 644 ./etc/niceshaper/$(clasfile) $(cfgdir)/$(clasfile)

uninstall: 
	@echo "###################"
	@echo "Uninstalling binary"
	@echo "###"
	rm -f $(bindir)/$(TARGET)

clean:
	@echo "###############"
	@echo "Cleaning source"
	@echo "###" 
	$(MAKE) -C src clean
	rm -f $(TARGET)

