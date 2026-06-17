# VanitySearch-allbtc (eharmanli Fork) - Optimized for Mass BTC Wallet Hunting

This is a highly optimized fork of VanitySearch-Bitcrack designed specifically for high-speed scanning of funded Bitcoin wallets and massive large-scale address databases.

## 🚀 Key Features & Optimizations

*   **GPU Bloom Filter (256MB):** Drastically reduces the bottleneck of binary searching on the GPU. Capable of handling massive databases (e.g., 34 Million addresses) with a false-positive rate of ~0.3%. This provides a massive speed boost by eliminating 99.7% of negative matches early.
*   **Batch Modular Inverse:** Optimized CUDA modular math. Computes 1 ModInv for 1024 points (GRP_SIZE=1024), achieving speeds ~1000x faster than traditional methods. Performance reaches up to 6900 MKeys/s on RTX 4090 and 8800 MKeys/s on RTX 5090.
*   **True Random Mode (`-random`):** In random mode, each GPU thread jumps to a mathematically randomized offset at each step, scanning 512 keys forward and 512 keys backward. This ensures optimal statistical coverage of massive 2^256 address spaces without getting stuck in sequential blocks.
*   **Reduced RAM/VRAM Usage:** Optimized memory footprint for loading massive binary databases (`database.bin`).
*   **Backup Mode (`-backup`):** Periodically saves progress (every ~60 seconds) during sequential searches. Allows you to resume exactly where you left off if the application closes unexpectedly. (Note: Not applicable in `-random` mode).
*   **Pause/Resume:** Press the `p` key at any time to pause the search and free up the GPU. Press `p` again to resume.

## 🛠️ Usage

```
VanitySearch.exe [-v] [-gpuId] [-i inputfile] [-o outputfile] [-start HEX] [-range] [-m] [-stop] [-random] [-backup]
```

### Parameters
*   `-v`: Print version.
*   `-i inputfile`: Input file containing addresses/prefixes, OR a binary database file (`database.bin`).
*   `-o outputfile`: File where the found private keys will be saved.
*   `-gpuId`: Target GPU ID (default is 0). *Note: This fork is optimized for single-GPU efficiency.*
*   `-start`: The starting Private Key in HEX format. In `-random` mode, this acts as the base reference point.
*   `-range`: The bit range dimension to scan. Scans from `start` to `(start + 2^range)`.
*   `-m`: Max number of prefixes found by each kernel call. Default is 262144 (must be a multiple of 65536).
*   `-random`: Activates Random Mode. Essential for massive ranges (like `2^256`) where sequential scanning is impossible.
*   `-backup`: Activates backup mode for sequential scans.
*   `-stop`: Stops the program automatically when all targeted addresses/prefixes are found.

### 💡 Database Creation & Simultaneous Scanning (`db_creator.cpp`)

This fork includes a highly optimized database creator (`db_creator.cpp`) that converts human-readable Bitcoin addresses from CSV/TSV files into raw binary `Hash160` payloads (`database.bin`).

**🔥 The "Simultaneous Scan" Advantage:**
Because Legacy (**P2PKH**, starts with `1`) and Native SegWit (**P2WPKH**, starts with `bc1q`) addresses both rely on the exact same 20-byte `Hash160` under the hood, `db_creator` merges them into a single `database.bin` file.
**This means VanitySearch scans for BOTH Legacy and Native SegWit addresses simultaneously in a single run without any performance penalty!** 

*(P2SH addresses starting with `3` are exported to a separate `database_p2sh.bin` file).*

**How to build your database:**
1.  **Download the data:** Visit [http://addresses.loyce.club/](http://addresses.loyce.club/) and download the latest `Blockchair_Bitcoin_addresses_latest.tsv.gz`. Extract it to get a list of funded addresses.
2.  **Run the Creator:** Compile and run `db_creator.exe` in the same folder as your CSV/TSV files.
    ```powershell
    # By default, it looks for "adresler.csv", "bcq1.csv", and "P2SH.csv"
    .\db_creator.exe
    
    # Or specify your own files:
    .\db_creator.exe -o database.bin -p2sh database_p2sh.bin my_addresses.csv
    ```
3.  **Output:** The tool deduplicates the addresses and creates `database.bin` (ready for VanitySearch) and `database_p2sh.bin`.

## 📝 Examples

**Windows:**
```powershell
# Basic sequential search for a single address within a 41-bit range
.\VanitySearch.exe -gpuId 0 -start 3BA89530000000000 -range 41 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ 

# Massive database scan using Random Mode over the entire 2^256 space
.\VanitySearch.exe -gpuId 0 -i database.bin -o found.txt -random -start 01de1cec280eae81de7f34c09362dbf27ec062546a14d58acf4e38030d7f2519 -range 256

# Resuming a sequential search using a backup file
.\VanitySearch.exe -gpuId 0 -start 3BA89530000000000 -range 41 -backup 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ 
```

**Linux:**
```bash
./vanitysearch -gpuId 0 -i database.bin -o found.txt -random -start 01de1cec... -range 256
```

## 📜 License
VanitySearch is licensed under GPLv3. Base project by Jean Luc PONS, Bitcrack fork by FixedPaul, optimizations by eharmanli.
