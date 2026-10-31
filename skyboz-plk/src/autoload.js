async function start_autoload() {

  function sceNetHtons(hostshort) {
    return ((hostshort & 0xff) << 8) | ((hostshort >> 8) & 0xff);
  }

  function file_exists(path) {
    const path_addr = alloc_string(path);
    const stat_buf = malloc(0x200n);
    const ret = syscall(SYSCALL.stat, path_addr, stat_buf);
    return ret === 0n;
  }

  function read_file_to_buffer(path) {
    const path_addr = alloc_string(path);
    const stat_buf = malloc(0x200n);
    if (syscall(SYSCALL.stat, path_addr, stat_buf) !== 0n) {
      throw new Error("read_file_to_buffer: stat failed for " + path);
    }
    const file_size = Number(read64(stat_buf + 72n));
    if (file_size <= 0) {
      throw new Error("read_file_to_buffer: invalid file size " + file_size);
    }

    const fd = syscall(SYSCALL.open, path_addr, O_RDONLY, 0n);
    if (fd < 0n) {
      throw new Error("read_file_to_buffer: open failed for " + path + " fd: " + toHex(fd));
    }

    const file_buffer = malloc(BigInt(file_size));
    let total_bytes_read = 0n;

    try {
      const bytes_read = syscall(SYSCALL.read, fd, file_buffer, BigInt(file_size));
      total_bytes_read = bytes_read;

      if (bytes_read < 0n) {
        throw new Error("read_file_to_buffer: read failed: " + toHex(bytes_read));
      }
      if (Number(bytes_read) !== file_size) {
        throw new Error(`read_file_to_buffer: incomplete read. Expected ${file_size}, got ${bytes_read}`);
      }
    } finally {
      syscall(SYSCALL.close, fd);
    }

    return { buffer: file_buffer, size: file_size };
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function find_file(filename) {
    const search = [
        "/mnt/sandbox/" + TITLE_ID + "_000/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/" + filename,
        "/mnt/sandbox/" + TITLE_ID + "_001/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/" + filename,
        "/mnt/sandbox/" + TITLE_ID + "_002/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/" + filename,
    ];
    for (const path of search) {
        if (file_exists(path)) {
            return path;
        }
    }
    return null;
  }

  // wait for elf_loader to start accepting connections
  let loader_active = false;
  const enable = malloc(4n);
  write32(enable, 1n);

  // Prepare sockaddr for 127.0.0.1:9021
  const sockaddr = malloc(16n);
  write8(sockaddr + 0n, 16n); // sin_len
  write8(sockaddr + 1n, AF_INET); // sin_family
  write16(sockaddr + 2n, BigInt(sceNetHtons(9021))); // sin_port
  write8(sockaddr + 4n, 127n); // 127.0.0.1
  write8(sockaddr + 5n, 0n);
  write8(sockaddr + 6n, 0n);
  write8(sockaddr + 7n, 1n);

  for (let i = 0; i < 200; i++) {
    const sockfd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
    if (sockfd >= 0n && sockfd < 0x100000n) {
      syscall(SYSCALL.setsockopt, sockfd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

      const connect_ret = syscall(SYSCALL.connect, sockfd, sockaddr, 16n);
      syscall(SYSCALL.close, sockfd);

      if (connect_ret === 0n) {
        loader_active = true;
        break;
      }
    }
    await sleep(25);
  }

  if (!loader_active) {
    await log("[ERROR] autoloader: elf_loader is not active");
    send_notification("[ERROR] elf_loader is not active");
    return;
  }

  const payload_name = "ps5-unified-autoloader.elf";
  const payload_path = find_file(payload_name);

  if (!payload_path) {
    const msg = "[-] Payload not found: " + payload_name;
    await log(msg);
    send_notification(msg);
    return;
  }

  await log("Loading payload from: " + payload_path);

  try {
    const { buffer, size } = read_file_to_buffer(payload_path);
    await log(`Payload size: ${size} bytes`);
    
    const sockfd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
    if (sockfd < 0n || sockfd >= 0x100000n) {
      throw new Error("socket creation failed: " + toHex(sockfd));
    }

    syscall(SYSCALL.setsockopt, sockfd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

    const connect_ret = syscall(SYSCALL.connect, sockfd, sockaddr, 16n);
    if (connect_ret !== 0n) {
      syscall(SYSCALL.close, sockfd);
      throw new Error("connect failed: " + toHex(connect_ret));
    }

    await log("Connected to loader. Writing ELF data...");
    const total_sent = syscall(SYSCALL.write, sockfd, buffer, BigInt(size));
    syscall(SYSCALL.close, sockfd);

    if (total_sent !== BigInt(size)) {
      throw new Error(`error sending elf data: expected ${size}, sent ` + toHex(total_sent));
    }

    const msg = `Successfully loaded unified autoloader`;
    await log(msg);
    send_notification(msg);

  } catch (e) {
    const errorMsg = "Payload Sender Error: " + e.message;
    await log(errorMsg);
    send_notification(errorMsg);
  }
}
