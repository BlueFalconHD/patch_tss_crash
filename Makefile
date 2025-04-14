CC = clang
CFLAGS = -Wall -Wextra -I/usr/local/include/kextrw
LDFLAGS = -L/usr/local/lib/kextrw -lkextrw
FRAMEWORKS = -framework IOKit -framework CoreFoundation
BUILD_DIR = build

CFLAGS += $(shell pkg-config --cflags capstone)
LDFLAGS += $(shell pkg-config --libs capstone)

all:
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) patch_tss_crash.c -o $(BUILD_DIR)/patch_tss_crash $(LDFLAGS) $(FRAMEWORKS)
	ldid -Sentitlements.plist $(BUILD_DIR)/patch_tss_crash

clean:
	rm -rf $(BUILD_DIR)/patch_tss_crash
	@echo "Cleaned up build files."
