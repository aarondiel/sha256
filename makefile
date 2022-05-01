CC := clang

sha256: sha256.c
	@$(CC) $^ -o $@
