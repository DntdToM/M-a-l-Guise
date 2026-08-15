# OBFU-mal — Phân tích & Ánh xạ Action

Nguồn: [OBFU-mal.txt](OBFU-mal.txt) (paper) + [OBFU-mal/src/obfumal/actions/](../OBFU-mal/src/obfumal/actions/) (code).

Paper giới thiệu 10 action trong Table III ("Expanded Action Space"): `Overlay Append`, `Imports Append`, `Section Rename`, `Remove Signature`, `Remove Debug`, `Section Append`, `Break Checksum`, `Change Timestamp`, `UPX Pack (Compress)`, và 3 biến thể `Darkarmour XOR EL1/EL2/EL3`. Toàn bộ action của OBFU-mal hoạt động trên **problem-space**: agent thao tác trực tiếp trên byte PE (qua LIEF hoặc công cụ CLI ngoài), sau đó ghi lại file `.exe` và gửi vào detector để tính reward. Không có hành động nào chỉ chạm feature vector.

---

## 1. Overlay Append

* **Hành động chuẩn hóa:** `OVERLAY_APPEND`
* **Tên gốc:** "Overlay Append" (Table III, "Additive — Append bytes to the end of malware exe")
* **Thao tác:** Thêm (Additive)
* **Chi tiết Triển khai:**
  * Vị trí: phần **overlay** ở cuối file (sau section cuối cùng, EOF), không nằm trong bất kỳ section nào và không được PE loader map vào memory → không phá chức năng.
  * Nội dung: chuỗi byte **ngẫu nhiên**. Theo [overlay_append.py](../OBFU-mal/src/obfumal/actions/classic/overlay_append.py#L15-L19):
    ```python
    length = 2 ** random.randint(self.min_log2, self.max_log2)   # 32..256 bytes
    upper = random.randrange(256)
    extension = bytes(random.randint(0, upper) for _ in range(length))
    return bytez + extension
    ```
  * Ngân sách: `2^5 = 32` đến `2^8 = 256` byte mỗi lần áp dụng; agent có thể gọi action nhiều lần trong một episode (quan sát trong Table VII: chuỗi `Overlay Append → Overlay Append`).
  * Lưu ý: paper của Anderson gốc dùng byte "benign-looking"; trong OBFU-mal code đơn giản là random bounded bytes.
* **Không gian & Khả năng đảo ngược:** **Problem-space hoàn toàn.** Thao tác thực hiện bằng phép nối byte `bytez + extension`, kết quả là file PE thực thi được vì overlay nằm ngoài vùng map-able — không cần patch header, không cần tính lại `SizeOfImage`. File sinh ra là executable hợp lệ, chức năng gốc giữ nguyên.

---

## 2. Imports Append

* **Hành động chuẩn hóa:** `IMPORTS_APPEND` (đồng thời là một dạng `IAT_INJECTION`)
* **Tên gốc:** "Imports Append" (Table III, "Additive — Add an entry to the import table")
* **Thao tác:** Thêm (Additive, sửa cấu trúc IAT)
* **Chi tiết Triển khai:**
  * Vị trí: **Import Directory / IAT** — thêm 1 entry (DLL + function) mới vào bảng import. Dùng LIEF parse PE, tìm DLL đã có hoặc thêm mới rồi gọi `lib.add_entry(func_name)`.
  * Nội dung: chọn ngẫu nhiên từ bảng `COMMON_IMPORTS` trong [imports_append.py:8-39](../OBFU-mal/src/obfumal/actions/classic/imports_append.py#L8-L39):
    * `KERNEL32.dll`: `GetTickCount`, `GetCurrentProcessId`, `GetLocalTime`, `GetSystemTime`, `GlobalAlloc`, `VirtualAlloc`, `CreateFileA`, `CreateFileW`
    * `USER32.dll`: `MessageBoxA/W`, `GetDesktopWindow`, `GetForegroundWindow`
    * `ADVAPI32.dll`: `RegOpenKeyExA`, `RegQueryValueExA`, `RegSetValueExA`
    * `SHELL32.dll`: `ShellExecuteA/W`
    * `WS2_32.dll`: `WSAStartup`, `socket`, `connect`
  * Ngân sách: 1 entry (1 DLL + 1 function) mỗi lần apply.
  * Sau khi sửa, gọi `build_binary_bytes(binary, build_imports=True)` để LIEF rebuild Import Table (cấp thêm space nếu cần).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** LIEF rebuild header + ghi lại một section `.l1` (hoặc tương tự) chứa Import Table mới, đồng thời cập nhật `DataDirectory[IMPORT_TABLE]`. Vì function được import nhưng không bao giờ được call ở runtime, IAT chỉ tăng trọng lượng "danh nghĩa" của file mà không thay đổi control flow — file vẫn là PE hợp lệ và chạy được. Đây cũng là lý do nó khai thác được đặc trưng `imports` của LightGBM/EMBER.

---

## 3. Section Rename

* **Hành động chuẩn hóa:** `SECTION_RENAME`
* **Tên gốc:** "Section Rename" (Table III, "Edit — Changes section's name in malware exe")
* **Thao tác:** Sửa (Edit)
* **Chi tiết Triển khai:**
  * Vị trí: field `Name` (8 byte) trong `IMAGE_SECTION_HEADER` của một section **chọn ngẫu nhiên**.
  * Giá trị gốc: tên section hiện tại (`.text`, `.data`, ...).
  * Giá trị mới: chọn random từ danh sách trong [section_rename.py:8-21](../OBFU-mal/src/obfumal/actions/classic/section_rename.py#L8-L21): `.text`, `.data`, `.rdata`, `.bss`, `.tls`, `.rsrc`, `.idata`, `.pdata`, `.reloc`, `.edata`, `.CRT`, `.INIT`. Bị cắt còn 7 ký tự: `section.name = new_name[:7]` → để chừa 1 byte null terminator trong field 8-byte.
  * Ngân sách: 1 section / lần apply.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Chỉ sửa metadata header. Tên section không ảnh hưởng tới cách PE loader load (loader chỉ dùng RVA/size/characteristics), nên file vẫn chạy. Đây là perturbation đánh vào feature `section_names` của LightGBM/EMBER.

---

## 4. Remove Signature

* **Hành động chuẩn hóa:** `REMOVE_SIGNATURE`
* **Tên gốc:** "Remove Signature" (Table III, "Edit — Unlink digital signature from certification table")
* **Thao tác:** Xóa/Sửa (unlink, không xóa byte thực)
* **Chi tiết Triển khai:**
  * Vị trí: `OptionalHeader.DataDirectory[CERTIFICATE_TABLE]` (index 4).
  * Giá trị gốc: `rva` + `size` trỏ tới bảng chứng chỉ trong overlay.
  * Giá trị mới: `directory.rva = 0; directory.size = 0` ([remove_signature.py:22-26](../OBFU-mal/src/obfumal/actions/classic/remove_signature.py#L22-L26)). Code chỉ chạy khi `has_signature(binary)` là True, ngược lại no-op.
  * Chú ý: **không xóa byte signature thật** trong overlay — chỉ "unlink" pointer. Các byte certificate vẫn tồn tại ở cuối file nhưng không được Windows nhận diện.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** File chạy được bình thường (chữ ký số không bắt buộc với PE executable, trừ khi có chính sách signing); đây là cách tháo gỡ "malware đã ký" để tránh các detector cho rằng đã-ký = lành tính, hoặc để phá hash chữ ký.

---

## 5. Remove Debug

* **Hành động chuẩn hóa:** `REMOVE_DEBUG`
* **Tên gốc:** "Remove Debug" (Table III, "Unlink debug section from header" — paper note là "Additive" nhưng đó là typo, đúng bản chất là Edit/Delete)
* **Thao tác:** Xóa (unlink)
* **Chi tiết Triển khai:**
  * Vị trí: `OptionalHeader.DataDirectory[DEBUG]` (index 6).
  * Logic giống RemoveSignature: nếu `binary.has_debug` thì set `rva = 0, size = 0` ([remove_debug.py:21-26](../OBFU-mal/src/obfumal/actions/classic/remove_debug.py#L21-L26)). Không xóa bytes `.debug$S/.debug$T` hoặc `IMAGE_DEBUG_DIRECTORY` thật — chỉ unlink pointer trong data directory.
  * Ngân sách: 1 data directory entry.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** File vẫn chạy được (debug info không cần cho execution). Mục tiêu là che PDB path / timestamp / GUID mà detector có thể coi là feature dấu vết.

---

## 6. Section Append  *(thực tế: fill slack space)*

* **Hành động chuẩn hóa:** `SECTION_APPEND_BYTES` / `SLACK_SPACE_FILL` (paper mô tả là "Add a new section" nhưng code là fill slack)
* **Tên gốc:** "Section Append" (Table III, "Additive — Add a new section to the malware exe")
* **Thao tác:** Thêm (vào slack space của section có sẵn)
* **Chi tiết Triển khai:**
  * Bất đồng bộ giữa paper và code. Code [section_append.py:18-40](../OBFU-mal/src/obfumal/actions/classic/section_append.py#L18-L40):
    ```python
    section = random.choice(binary.sections)
    length = 2 ** random.randint(self.min_log2, self.max_log2)   # 32..256
    available = section.size - len(section.content)              # slack có sẵn
    if available <= 0: return bytez
    if length > available: length = available
    section.content = base_content + [random.randint(0, upper) for _ in range(length)]
    ```
  * Vị trí: **slack space** (`VirtualSize - SizeOfRawData` hoặc vùng đệm align) trong **một section chọn ngẫu nhiên**. Không thêm section mới mặc dù paper mô tả như vậy.
  * Nội dung: byte random bounded (`0..upper`, upper chọn 0..255).
  * Ngân sách: 32–256 byte / lần, cắt theo `available` còn trống.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Vì ghi vào slack có sẵn (không vượt quá `section.size`), không cần update `SizeOfImage` hay relocate. LIEF rebuild giữ nguyên layout; file PE vẫn chạy.

---

## 7. Break Checksum

* **Hành động chuẩn hóa:** `BREAK_CHECKSUM`
* **Tên gốc:** "Break Checksum" (Table III, "Edit — Set file's checksum")
* **Thao tác:** Sửa
* **Chi tiết Triển khai:**
  * Vị trí: `OptionalHeader.CheckSum` (offset 64 trong Optional Header).
  * Giá trị gốc: giá trị checksum được compiler/linker tính.
  * Giá trị mới: `binary.optional_header.checksum = 0` ([break_checksum.py:21](../OBFU-mal/src/obfumal/actions/classic/break_checksum.py#L21)). Đây là cách làm "mất hợp lệ" checksum một cách đơn giản (0 là giá trị "skip check" trên user-mode PE).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** User-mode EXE không bị Windows từ chối khi checksum sai/0; chỉ kernel driver yêu cầu checksum hợp lệ. Nên file vẫn chạy. Đánh vào feature `header_checksum` của static detector.

---

## 8. Change Timestamp

* **Hành động chuẩn hóa:** `TIMESTAMP`
* **Tên gốc:** "Change Timestamp" (Table III, "Edit — Change / set timestamp")
* **Thao tác:** Sửa
* **Chi tiết Triển khai:**
  * Vị trí: `FileHeader.TimeDateStamp` (IMAGE_FILE_HEADER offset 4).
  * Giá trị gốc: timestamp của linker.
  * Giá trị mới: `binary.header.time_date_stamps = int(time.time())` ([change_timestamp.py:23](../OBFU-mal/src/obfumal/actions/classic/change_timestamp.py#L23)) — set thành thời điểm hiện tại (epoch seconds).
  * Lưu ý thú vị: Table VII chỉ ra sequence "Change TDS → Overlay Append" xuất hiện **94 lần** — là một trong những chuỗi evasive phổ biến nhất, cho thấy feature `header_timestamp` có trọng số đáng kể ở EMBER/MalConv.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Timestamp không ảnh hưởng gì đến loader → file chạy bình thường.

---

## 9. UPX Pack

* **Hành động chuẩn hóa:** `UPX_PACK` (và `PACKING`)
* **Tên gốc:** "UPX Pack (Compress)" (Table III, "Obfuscate — Compress malware exe")
* **Thao tác:** Sửa toàn bộ file (nén)
* **Chi tiết Triển khai:**
  * Cơ chế: gọi binary `upx` qua subprocess ([pack_adapter.py:28-43](../OBFU-mal/src/obfumal/actions/obfuscation/pack_adapter.py#L28-L43)). Ghi bytez ra temp file, chạy UPX, đọc lại output.
  * Flags:
    ```python
    options = ["--force", "--overlay=copy"]
    options += [f"-{random.randint(1,9)}"]                   # compression level
    options += [f"--compress-exports={random.randint(0,1)}"]
    options += [f"--compress-icons={random.randint(0,3)}"]
    options += [f"--compress-resources={random.randint(0,1)}"]
    options += [f"--strip-relocs={random.randint(0,1)}"]
    ```
  * Kết quả: UPX thay thế các section gốc bằng `UPX0` (destination rỗng) + `UPX1` (dữ liệu nén) và stub giải nén; `AddressOfEntryPoint` trỏ vào stub.
  * Ngân sách: toàn file (whole-file packing). Timeout 15s.
  * Đáng chú ý: paper (Section IV.C) chỉ rõ UPX-packed malware thường bị detector coi là malicious → evasion rate thấp hơn, vì vậy OBFU-mal thêm DarkarmourXOR để thay thế/kết hợp.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** UPX sinh ra PE thực thi hợp lệ (self-unpacking stub). Khi chạy, stub giải nén `UPX1` ngược lại vào memory rồi jump về OEP → functionality preserved. Đã có test trên file thực.

---

## 10. Darkarmour XOR EL1 / EL2 / EL3

* **Hành động chuẩn hóa:** `XOR_ENCRYPTION`
* **Tên gốc:** "Darkarmour XOR EL1", "Darkarmour XOR EL2", "Darkarmour XOR EL3" (Table III). EL = "Encryption Loop"; 3 action là 1, 2, hoặc 3 vòng XOR.
* **Thao tác:** Sửa toàn bộ file (mã hóa + wrap bằng loader stub)
* **Chi tiết Triển khai:**
  * Cơ chế: gọi tool `darkarmour.py` ([xor_adapter.py:34-57](../OBFU-mal/src/obfumal/actions/obfuscation/xor_adapter.py#L34-L57)) với tham số:
    ```
    darkarmour.py -f <input.exe> --encrypt xor --loop <1|2|3> -o <out.exe> -j
    ```
    Flag `-j` = "jmp loader" (loại loader nạp tại memory).
  * Bản chất của Darkarmour (xem [darkarmour-master/darkarmour.py](../OBFU-mal/darkarmour-master/darkarmour-master/darkarmour.py)): sinh key ngẫu nhiên, XOR-encrypt toàn bộ byte của PE gốc (có thể lặp 1–3 vòng với 1–3 key khác nhau), rồi nhúng blob đã mã hóa + stub C (đã biên dịch) vào một **PE dropper mới**. Stub khi chạy: cấp phát memory (VirtualAlloc), giải XOR blob, rồi execute in-memory (reflective-load-style) hoặc jump thẳng vào payload đã decode.
  * EL1/EL2/EL3 khác nhau ở số vòng XOR — nhiều vòng ⇒ byte entropy khác biệt với stub 1-loop, evasion rate cao hơn ở một số category (xem Table VII: `Darkarmour XOR EL2` xuất hiện làm action cuối trong hầu hết sequences evasive).
  * Paper note: "execution does not require bytes touching the disk" — tức là payload gốc không ghi lại ra disk, chỉ chạy in-memory.
  * Ngân sách: toàn file; 1 lần apply tạo ra 1 binary mới có kích thước ≈ |stub| + |encrypted original|.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Output là PE mới hoàn toàn (file dropper) với OEP mới trỏ vào stub giải mã. File chạy được; payload gốc được restore ở runtime trong memory, giữ nguyên chức năng malware ban đầu (paper Section VIII xác nhận đã test functionality qua VirusTotal). Đây là một dạng `DROPPER` + `XOR_ENCRYPTION` + `PACKING` kết hợp, nhưng OBFU-mal tính nó là 1 action (theo loop-level).

---

## Bảng ánh xạ tóm tắt

| Tên trong paper OBFU-mal | Tên chuẩn hóa | Thao tác | Problem/Feature space |
|---|---|---|---|
| Overlay Append | `OVERLAY_APPEND` | Thêm (EOF) | Problem |
| Imports Append | `IMPORTS_APPEND` (∈ `IAT_INJECTION`) | Thêm (IAT entry) | Problem |
| Section Rename | `SECTION_RENAME` | Sửa (header name) | Problem |
| Remove Signature | `REMOVE_SIGNATURE` | Xóa (unlink DataDir[CERT]) | Problem |
| Remove Debug | `REMOVE_DEBUG` | Xóa (unlink DataDir[DEBUG]) | Problem |
| Section Append | `SECTION_APPEND_BYTES` / `SLACK_SPACE_FILL` (code) ; paper nói `SECTION_ADD` | Thêm (slack) | Problem |
| Break Checksum | `BREAK_CHECKSUM` | Sửa (checksum = 0) | Problem |
| Change Timestamp | `TIMESTAMP` | Sửa | Problem |
| UPX Pack (Compress) | `UPX_PACK` / `PACKING` | Nén toàn file | Problem |
| Darkarmour XOR EL1/EL2/EL3 | `XOR_ENCRYPTION` (+ `DROPPER`) | Mã hóa + wrap dropper | Problem |

## Ghi chú quan trọng

1. **Không có action nào thuần Feature-space.** Toàn bộ 10 action đều chỉnh sửa byte PE thực (qua LIEF hoặc tool CLI) rồi rebuild file. Reward từ detector được tính trên file đã ghi ra disk. Do đó mọi adversarial sample đều là `.exe` thực thi được (được test trên VirusTotal sandbox, xem Section VI Case Study với ClamAV).
2. **Chuỗi action là chìa khóa** (Table VII): action mạnh nhất là kết hợp — ví dụ `Change TDS → Overlay Append → Darkarmour XOR EL2` (58 occurrences vs LGBM/EMBER). RL-DQN học được rằng obfuscation nặng (XOR) nên đặt sau cùng để không bị overwrite bởi các action khác.
3. **Action space trong OBFU-mal = 10** (không phải 30 như danh sách canonical). Những action canonical không có trong paper này: `HEADER_PERTURB`, `SLACK_SPACE_FILL` (explicit — code OBFU-mal implicit dùng slack qua SectionAppend), `DOS_HEADER_MOD/EXT`, `CONTENT_SHIFT`, `CODE_REWRITE_*`, `CODE_TRANSLATION`, `NEW_ENTRYPOINT` (một phần ẩn trong XOR dropper), `CFG_EDGE_REDIVIDE`, `SEMANTIC_NOP_INJECT`, `BYTECODE_API_HIJACKING`, `CODE_RANDOMIZE`, `UPX_UNPACK`.
4. **Không có "inverse" action** (unpack, un-XOR) trong action space của OBFU-mal — agent chỉ thêm obfuscation, không gỡ.

---
---

# DQEAF — Phân tích & Ánh xạ Action

Nguồn: [DQEAF.txt](DQEAF.txt) (Z. Fang et al., "Evading Anti-Malware Engines With Deep Reinforcement Learning", IEEE Access 2019) + [DQEAF/src/dqeaf/actions.py](../DQEAF/src/dqeaf/actions.py) (code).

DQEAF cố ý **giới hạn action space xuống 4** (`A = {ARBE, ARI, ARS, RS}`, paper Section III-D) để dễ training và để mỗi action đảm bảo "functionality-preserving". So với Anderson et al. 2018 (10+ action), DQEAF ít hơn nhưng claim success rate ~75%. Cả 4 đều chạy trên **problem-space**: áp trực tiếp lên byte PE qua LIEF, sau đó write file và cho classifier đánh label (benign/malicious) → reward. Feature extractor dùng byte histogram + 2D entropy histogram từ raw binary, nhưng feature chỉ được observe để DQN chọn action, không phải chỗ action tác động.

Kiến trúc thực thi đáng chú ý trong code: mỗi action LIEF-based chạy trong một `ProcessPoolExecutor` spawn worker (timeout 5s), vì LIEF C++ hay segfault trên edge case PE ([actions.py:151-195](../DQEAF/src/dqeaf/actions.py#L151-L195)). Nếu worker chết/hang, action trả về bytez gốc (no-op).

---

## 1. ARBE — Append Random Bytes to End

* **Hành động chuẩn hóa:** `OVERLAY_APPEND`
* **Tên gốc:** "ARBE. Append random bytes to the end of PE file" (paper Section III-D, điểm 1)
* **Thao tác:** Thêm (Additive)
* **Chi tiết Triển khai:**
  * Vị trí: cuối file, sau section cuối cùng → rơi vào **overlay** (không được PE loader map).
  * Nội dung: byte random đầy đủ dải `0..255`. Không có constraint "benign-looking".
  * Ngân sách: **32–512 byte / lần apply** ([actions.py:61-64](../DQEAF/src/dqeaf/actions.py#L61-L64)):
    ```python
    def _append_random_bytes(data, rng):
        n = rng.randint(32, 512)
        suffix = bytes(rng.randint(0, 255) for _ in range(n))
        return data + suffix
    ```
  * Đây là "fast path" không qua LIEF parser → rẻ nhất trong 4 action, được dùng không qua ProcessPool ([actions.py:172-173](../DQEAF/src/dqeaf/actions.py#L172-L173)).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Nối byte thuần túy, file PE vẫn chạy được vì overlay nằm ngoài vùng được loader map. Không cần sửa bất kỳ header nào.

---

## 2. ARI — Append Random Import

* **Hành động chuẩn hóa:** `IMPORTS_APPEND` (∈ `IAT_INJECTION`)
* **Tên gốc:** "ARI. Append a randomly named library with random function name to the import address table of PE file" (paper Section III-D, điểm 2)
* **Thao tác:** Thêm (IAT entry mới)
* **Chi tiết Triển khai:**
  * Vị trí: Import Directory / IAT (qua `binary.add_library(...).add_entry(...)`).
  * Nội dung: **tên DLL và tên function đều là ASCII random** — không phải whitelist như OBFU-mal ([actions.py:67-77](../DQEAF/src/dqeaf/actions.py#L67-L77)):
    ```python
    lib_name = _random_ascii(rng, 5, 10).lower() + ".dll"   # ví dụ "qvmhka.dll"
    func_name = _random_ascii(rng, 6, 16)                    # ví dụ "NqAbCdeFgh"
    imp = binary.add_library(lib_name)
    imp.add_entry(func_name)
    ```
  * Ngân sách: 1 DLL + 1 function / lần.
  * **Hệ quả quan trọng:** DLL tên random không tồn tại thực tế → nếu loader thực sự resolve import thì sẽ crash file. DQEAF dựa vào việc **classifier chỉ đọc byte histogram / entropy**, không thực thi file, nên "functionality-preserving" ở đây được hiểu là PE header vẫn valid (parse được), không phải là file chạy được trên máy Windows thật. Paper claim Algorithm 1 + "amend RVA" để bảo toàn, nhưng import tới DLL không tồn tại vẫn phá runtime.
* **Không gian & Khả năng đảo ngược:** **Problem-space về mặt byte**, nhưng trên thực tế file sinh ra **không đảm bảo chạy được** trên Windows thật (Windows loader fail resolve DLL không tồn tại → "DLL not found"). So với OBFU-mal (dùng pool DLL/function thật) thì DQEAF yếu hơn về functional integrity, chỉ pass được static byte-based detector.

---

## 3. ARS — Append Random Section

* **Hành động chuẩn hóa:** `SECTION_ADD`
* **Tên gốc:** "ARS. Append a randomly named section to the section table of PE file" (paper Section III-D, điểm 3). Có 7 subtype: ARS-BSS, ARS-UNKNOWN, ARS-IDATA, ARS-RELOC, ARS-RSRC, ARS-TEXT, ARS-TLS — paper coi là một action duy nhất (enum `ARS = 2`), subtype chọn ngẫu nhiên bên trong.
* **Thao tác:** Thêm (section mới)
* **Chi tiết Triển khai:**
  * Vị trí: cuối section table → `binary.add_section(sec)` (LIEF tự tính RVA/raw offset, cập nhật `SizeOfImage`, `NumberOfSections`).
  * Tên section: `"." + ASCII random 4-7 ký tự`, ví dụ `.QjxAbC` ([actions.py:102](../DQEAF/src/dqeaf/actions.py#L102)).
  * Nội dung: **128–1024 byte random** `0..255` ([actions.py:103](../DQEAF/src/dqeaf/actions.py#L103)).
  * Characteristics theo subtype ([actions.py:80-94](../DQEAF/src/dqeaf/actions.py#L80-L94)):
    * BSS: `CNT_UNINITIALIZED_DATA | MEM_READ | MEM_WRITE`
    * IDATA / RSRC: `CNT_INITIALIZED_DATA | MEM_READ`
    * RELOC: `CNT_INITIALIZED_DATA | MEM_READ | MEM_DISCARDABLE`
    * TEXT: `CNT_CODE | MEM_EXECUTE | MEM_READ`
    * TLS: `CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE`
    * UNKNOWN / default: `CNT_INITIALIZED_DATA | MEM_READ`
  * Subtype được sample ngẫu nhiên mỗi lần apply, tạo ra diversity trong feature (byte histogram phụ thuộc content + entropy phụ thuộc nhiều section).
  * Paper Algorithm 1 (Section III-D) mô tả: parse `bint` → create new section → fill content → amend RVA (`RVA_new = max RVA_sections`) → ghép vào `bint+1`. Code để LIEF builder làm việc này tự động.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Section được thêm đúng cách, PE header được rebuild. Section mới không bao giờ được jump vào (không set EP tới đó), không có TLS callback đăng ký → payload gốc vẫn chạy bình thường.

---

## 4. RS — Remove Signature

* **Hành động chuẩn hóa:** `REMOVE_SIGNATURE`
* **Tên gốc:** "RS. Remove signature from certificate table of the DataDirectory" (paper Section III-D, điểm 4)
* **Thao tác:** Xóa (unlink + có thể clear signature object)
* **Chi tiết Triển khai:**
  * Vị trí: `DataDirectory[4]` = `CERTIFICATE_TABLE`.
  * Code thực hiện 2 bước ([actions.py:112-132](../DQEAF/src/dqeaf/actions.py#L112-L132)):
    1. Nếu LIEF version có `remove_all_signatures`, gọi nó; ngược lại nếu `has_signatures` thì `signatures.clear()` — xóa **signature object** khỏi binary (LIEF sẽ không ghi lại khối certificate vào overlay khi rebuild).
    2. Set `cert_dir.rva = 0; cert_dir.size = 0` trong data directory.
  * So với OBFU-mal: OBFU-mal chỉ unlink pointer (byte signature vẫn còn ở overlay); DQEAF unlink **và** xóa signature object → clean hơn, file output không còn byte chứng chỉ nếu LIEF rebuild đúng.
  * Ngân sách: 1 data directory entry + signature blob.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** File user-mode PE không cần chữ ký số để chạy → vẫn thực thi được. Phá hash/chữ ký gốc, nhưng đây là mục đích.

---

## Bảng ánh xạ tóm tắt — DQEAF

| Paper name | Canonical | Thao tác | Vị trí | Ngân sách |
|---|---|---|---|---|
| ARBE | `OVERLAY_APPEND` | Thêm | EOF (overlay) | 32–512 byte |
| ARI  | `IMPORTS_APPEND` / `IAT_INJECTION` | Thêm | Import Table (DLL + func random) | 1 entry |
| ARS  | `SECTION_ADD` | Thêm | Section Table (7 subtype BSS/UNKNOWN/IDATA/RELOC/RSRC/TEXT/TLS) | 128–1024 byte |
| RS   | `REMOVE_SIGNATURE` | Xóa | `DataDir[CERTIFICATE_TABLE]` + signature object | 1 entry |

## Ghi chú quan trọng — DQEAF

1. **Action space nhỏ (4 action) là chủ ý** — paper Section III-D lập luận: "Reinforcement learning with extremely large action spaces will increase the difficulty of model training." Đây là khác biệt thiết kế rõ rệt với OBFU-mal (10 action) và gym-malware/Anderson (10+).
2. **Toàn bộ 4 action là Additive hoặc Delete pointer, không có Modify/Edit** nào trên phần byte đã có (khác OBFU-mal có Rename/Checksum/Timestamp). Điều này đơn giản hóa chứng minh "functionality-preserving".
3. **ARI có lỗ hổng functional preservation**: tên DLL random `.lower() + ".dll"` không tồn tại thực → nếu classifier eval sandbox-based thay vì static, file sẽ fail ở load time. DQEAF chỉ target static byte-histogram classifier nên không gặp vấn đề này trong benchmark của họ, nhưng khi dùng DQEAF AE để retrain defender, cần ghi nhớ giới hạn.
4. **ARS là 1 action logic, 7 subtype ngẫu nhiên bên trong** — khi liệt kê canonical action, vẫn tính là 1 `SECTION_ADD`. Subtype chỉ tác động đến `Characteristics` field của section header, không phải action riêng biệt.
5. Các canonical action **không có** trong DQEAF: `HEADER_PERTURB`, `SLACK_SPACE_FILL`, `DOS_HEADER_*`, `CONTENT_SHIFT`, `PACKING`/`UPX_*`, `XOR_ENCRYPTION`, `DROPPER`, `SECTION_RENAME`, `REMOVE_DEBUG`, `BREAK_CHECKSUM`, `TIMESTAMP`, `NEW_ENTRYPOINT`, và toàn bộ nhóm code-level (`CODE_REWRITE_*`, `CODE_TRANSLATION`, `CODE_RANDOMIZE`, `CFG_*`, `SEMANTIC_NOP_INJECT`, `BYTECODE_API_HIJACKING`).
6. **Runtime safety layer** (không có trong paper): code wrap mọi LIEF action vào `ProcessPoolExecutor` với timeout 5s + SIGKILL-on-hang ([actions.py:165-195](../DQEAF/src/dqeaf/actions.py#L165-L195)). Nếu segfault/timeout → trả về bytez gốc (no-op). Đáng lưu ý khi reproduce kết quả trên dataset lớn.

---
---

# MAB-malware — Phân tích & Ánh xạ Action

Nguồn: [MAB-Malware.txt](MAB-Malware.txt) (Song et al., "MAB-Malware: A Reinforcement Learning Framework for Blackbox Generation of Adversarial Malware", AsiaCCS 2022) + [MAB-malware/core/arm.py](../MAB-malware/core/arm.py) (định nghĩa 8 class `Arm*`) + [MAB-malware/rewriter.py](../MAB-malware/rewriter.py) (Code Randomization).

**Khác biệt thiết kế so với OBFU-mal/DQEAF:**
- MAB-malware mô hình action-content pair như **slot machine** của một multi-armed bandit (Thompson sampling), **stateless** — không dùng DQN/MDP. Insight: phần lớn action độc lập, chỉ cần 1–2 action essential để evade.
- Sau khi sinh AE, có **Action Minimizer** ([attacks/minimizer.py](../MAB-malware/attacks/minimizer.py)) loại bỏ action thừa và thay action "macro" bằng biến thể nhỏ nhất gọi là **micro-action**. Reward chỉ gán cho essential micro-action → chính xác hơn.
- **Hai lớp action (Table 1 paper):**
  - **Macro** (8): OA, SP, SA, SR, RC, RD, BC, CR
  - **Micro** (5): OA1, SP1, SA1, SR1, CP1 — cùng loại thao tác nhưng budget = 1 byte để tối thiểu hóa thay đổi feature
- Bảng "Affected Features" (Table 2) gán mỗi action vào một subset của {F1 File Hash, F2 Section Hash, F3 Section Count, F4 Section Name, F5 Section Padding, F6 Debug Info, F7 Checksum, F8 Certificate, F9 Code Sequence, F10 Data Distribution}. Micro-action được xây để chỉ chạm **một** feature trong số này.

Tất cả action đều chạy trên **problem-space** — thao tác byte qua `pefile` (LIEF không dùng). Functional integrity được verify bằng `try_parse_pe` sau mỗi transform; nếu không parse được thì restore file gốc (`cp -p`) → action degrade thành no-op.

---

## 1. OA — Overlay Append (Macro)

* **Hành động chuẩn hóa:** `OVERLAY_APPEND`
* **Tên gốc:** "OA — Overlay Append — Appends benign contents at the end of a binary" (Table 1)
* **Thao tác:** Thêm (EOF)
* **Chi tiết Triển khai:** [arm.py:105-152](../MAB-malware/core/arm.py#L105-L152):
  ```python
  with open(output_path, 'ab') as f:
      f.write(self.content)
  ```
  * Vị trí: append vào cuối file (sau section cuối → overlay).
  * Nội dung: `self.content` được lấy từ `Utils.get_random_content()` — **không phải byte random**, mà là chunk **benign content** được extract sẵn từ binary sạch (xem `common/utils.py`, pool `get_random_content`). Điểm khác biệt then chốt so với DQEAF/gym-malware: content có distribution giống file thật.
  * Ngân sách: kích thước chunk benign (thường hàng KB).
  * Slot machine "cache" content khi thành công: `update_description()` dùng md5(content)[:8] làm ID → cùng content tái sử dụng cho malware khác (paper Section 4).
* **Affected features:** F1 (File Hash), F10 (Data Distribution).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Append thuần vào overlay, PE chạy được.

---

## 2. SP — Section Append (Macro) *— không phải thêm section mà là fill slack*

* **Hành động chuẩn hóa:** `SECTION_APPEND_BYTES` / `SLACK_SPACE_FILL`
* **Tên gốc:** "SP — Section Append — Appends random bytes to the unused space at the end of a section"
* **Thao tác:** Thêm (vào slack space)
* **Chi tiết Triển khai:** [arm.py:310-434](../MAB-malware/core/arm.py#L310-L434):
  * Scan tất cả section, tính `available_size = get_available_size_safe(pe, idx)` — slack giữa `Misc_VirtualSize` và section tiếp theo (hoặc `PointerToOverlay` nếu là section cuối).
  * Chọn ngẫu nhiên section có slack > 0; content lặp lại từ pool benign cho đến khi đủ `available_size` rồi cắt (`append_content = content[:available_size]`).
  * Ghi vào đúng offset `PointerToRawData + Misc_VirtualSize` (nằm trong raw size đã allocated, không cần resize file):
    ```python
    pe.set_bytes_at_offset(
        target_section.PointerToRawData + target_section.Misc_VirtualSize,
        append_content)
    ```
  * Vì ghi vào vùng đã tồn tại trong raw data, không cần update `SizeOfImage`, không cần thêm section header mới — đây là lý do nó gọi là "section append" nhưng thực chất là **slack fill**. Paper OBFU-mal cũng bị mismatch cùng kiểu.
* **Affected features:** F2 (Section Hash), F5 (Section Padding).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** File chạy được; slack data không bao giờ được reference ở runtime.

---

## 3. SA — Section Add (Macro)

* **Hành động chuẩn hóa:** `SECTION_ADD`
* **Tên gốc:** "SA — Section Add — Adds a new section with benign contents"
* **Thao tác:** Thêm (section header mới + raw content mới)
* **Chi tiết Triển khai:** [arm.py:579-722](../MAB-malware/core/arm.py#L579-L722) — đây là implementation **thủ công** không dùng LIEF builder, khác biệt so với DQEAF/OBFU-mal:
  1. Dùng slot trống ngay sau section header cuối (offset `last_section.get_file_offset() + 40`). Kiểm tra vùng này:
     * Có đủ 40 byte trước section đầu tiên không?
     * Nội dung có **toàn 0** không (`next_header_space_content_sum == 0`) — nếu có dữ liệu ẩn (vd. VB header), abort.
  2. Resize file raw: `map.resize(original_size + raw_size)` với `raw_size = align(len(content), FileAlignment)`.
  3. Ghi 40 byte section header mới:
     ```python
     characteristics = 0xE0000020   # CODE|EXECUTE|READ|WRITE — MEM_WRITE|MEM_EXECUTE|MEM_READ|CNT_CODE
     pe.set_bytes_at_offset(hdr + 0,  section_name[:8])
     pe.set_dword_at_offset(hdr + 8,  virtual_size)
     pe.set_dword_at_offset(hdr + 12, virtual_offset)
     pe.set_dword_at_offset(hdr + 16, raw_size)
     pe.set_dword_at_offset(hdr + 20, raw_offset)
     pe.set_dword_at_offset(hdr + 36, characteristics)
     ```
  4. `pe.FILE_HEADER.NumberOfSections += 1`, `SizeOfImage = virtual_size + virtual_offset`.
  5. Ghi content vào `raw_offset = file_size` (append vào cuối).
  * `section_name` và `content` đều từ `Utils.get_random_content()` → tên + data chunk lấy từ benign binary pool.
* **Affected features:** F3 (Section Count), F10 (Data Distribution).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** File vẫn chạy được vì section mới không trỏ tới từ EP và loader bỏ qua section không được reference. Có 2 rủi ro edge case: nếu không có slot header trống → skip; nếu có VB header ẩn trong slot → skip.

---

## 4. SR — Section Rename (Macro)

* **Hành động chuẩn hóa:** `SECTION_RENAME`
* **Tên gốc:** "SR — Section Rename — Change the section name to a name in benign binaries"
* **Thao tác:** Sửa (field Name)
* **Chi tiết Triển khai:** [arm.py:486-577](../MAB-malware/core/arm.py#L486-L577):
  * Chọn random 1 section, lấy tên mới từ `Utils.get_random_content()` (tên section của binary sạch trong pool). Loop cho đến khi `new_name != old_name`.
  * `pe.sections[section_idx].Name = new_name.encode()`.
  * Cache `section_idx`, `old_name`, `new_name` trong arm để tái sử dụng (khác DQEAF re-random mỗi lần).
* **Affected features:** F4 (Section Name).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Tên section không ảnh hưởng loader.

---

## 5. RC — Remove Certificate (Macro)

* **Hành động chuẩn hóa:** `REMOVE_SIGNATURE`
* **Tên gốc:** "RC — Remove Certificate — Zero out the signed certificate of a binary"
* **Thao tác:** Xóa (zero-out + unlink)
* **Chi tiết Triển khai:** [arm.py:204-245](../MAB-malware/core/arm.py#L204-L245):
  ```python
  if d.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
      if d.VirtualAddress > 0:
          size_in_sig = pe.get_word_from_offset(d.VirtualAddress)
          if size_in_sig == d.Size:
              pe.set_bytes_at_offset(d.VirtualAddress, ('\x00' * d.Size).encode())
              d.VirtualAddress = 0
              d.Size = 0
  ```
  * **Khác 2 paper trước:** MAB-malware **zero-out toàn bộ byte chữ ký** trong overlay (`'\x00' * d.Size`) **rồi** mới unlink pointer. Sạch nhất trong 3 paper.
  * Sanity check: `size_in_sig == d.Size` để chắc chắn pointer hợp lệ trước khi ghi.
* **Affected features:** F8 (Certificate).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** File chạy được.

---

## 6. RD — Remove Debug (Macro)

* **Hành động chuẩn hóa:** `REMOVE_DEBUG`
* **Tên gốc:** "RD — Remove Debug — Zero out the debug information in a binary"
* **Thao tác:** Xóa (zero-out + unlink)
* **Chi tiết Triển khai:** [arm.py:154-202](../MAB-malware/core/arm.py#L154-L202):
  * Tìm `IMAGE_DIRECTORY_ENTRY_DEBUG`, parse `debug_directory`. Nếu `debug_type == 2` (CodeView / PDB info), lưu `(file_offset, segment_size)` của segment PDB.
  * Set `d.VirtualAddress = 0; d.Size = 0`.
  * Sau khi `pe.write`, tự zero-out **segment PDB thật** trong file output qua `zero_out_file_content(output_path, file_offset, segment_size)` — vì `set_bytes_at_offset` của pefile đôi khi không take effect cho debug data.
* **Affected features:** F6 (Debug Info).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** File chạy được; xóa hoàn toàn PDB path/GUID.

---

## 7. BC — Break Checksum (Macro)

* **Hành động chuẩn hóa:** `BREAK_CHECKSUM`
* **Tên gốc:** "BC — Break Checksum — Zero out the checksum value in the optional header"
* **Thao tác:** Sửa
* **Chi tiết Triển khai:** [arm.py:279-308](../MAB-malware/core/arm.py#L279-L308):
  ```python
  pe.OPTIONAL_HEADER.CheckSum = 0
  pe.write(output_path)
  ```
* **Affected features:** F7 (Checksum).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** User-mode EXE không bắt buộc checksum đúng.

---

## 8. CR — Code Randomization (Macro) *— phức tạp nhất*

* **Hành động chuẩn hóa:** `CODE_RANDOMIZE` (+ chạm `SEMANTIC_NOP_INJECT` và `CFG_EDGE_REDIVIDE` qua basic block reordering)
* **Tên gốc:** "CR — Code Randomization — Replace instruction sequence with semantically equivalent one" (Table 1). Paper credit: "We also adopt a code randomization action (CR) from Pappas et al." (ROP defense technique).
* **Thao tác:** Sửa tại byte-level bên trong `.text` — viết lại instruction mà không đổi semantic.
* **Chi tiết Triển khai:** [rewriter.py:1040-1124](../MAB-malware/rewriter.py#L1040-L1124) — dùng **IDA Pro headless** + Capstone:
  1. `_run_ida_headless` gọi IDA qua script [scripts/ida_dump_cfg.py](../MAB-malware/scripts/ida_dump_cfg.py) để dump metadata CFG (function, basic block, instruction với bytes, CS-operand info). Timeout mặc định 900s.
  2. `PEBufferEditor` load file vào bytearray mutable, xử lý relocation entries để biết instruction nào chứa địa chỉ tuyệt đối không được di chuyển.
  3. Áp 4 transform theo thứ tự cố định ([rewriter.py:44-49](../MAB-malware/rewriter.py#L44-L49)):

     * **`register_reassignment`** ([rewriter.py:777-833](../MAB-malware/rewriter.py#L777-L833)): trong phạm vi 1 function, tìm cặp GPR `(A, B)` mà A và B không conflict về liveness, rồi **swap** mọi reference trong mọi instruction (patch ModR/M + SIB byte qua `_patch_register_swap`). Ví dụ: mọi `mov eax, ...` / `add eax, ebx` → `mov esi, ...` / `add esi, ebx` nếu swap (eax, esi). Bảo toàn prologue/epilogue conventions bằng cách loại push/pop/ret/call khỏi phạm vi swap.
     * **`register_preservation_reordering`** ([rewriter.py:863-927](../MAB-malware/rewriter.py#L863-L927)): trong prologue (`push r1; push r2; push r3`) và epilogue đối xứng (`pop r3; pop r2; pop r1`), permute thứ tự push và rewrite epilogue pop tương ứng (opcode `0x50 + reg_code` / `0x58 + reg_code`). Không đổi semantic vì các push chỉ "preserve" GPR.
     * **`basic_block_reordering`** ([rewriter.py:929-967](../MAB-malware/rewriter.py#L929-L967)): hoán đổi thứ tự basic block trong 1 function. Edge bị cắt sẽ được "reconnect" qua jmp patch — đây là chạm khái niệm `CFG_EDGE_REDIVIDE` trong canonical list.
     * **`atomic_substitution`** ([rewriter.py:969-1011](../MAB-malware/rewriter.py#L969-L1011)): thay 1 instruction bằng cặp tương đương cùng độ dài theo bảng `SAME_LENGTH_DUAL_OPCODE_FAMILIES` ([rewriter.py:80-98](../MAB-malware/rewriter.py#L80-L98)) — ví dụ `add r/m32, r32` (`0x01`) ↔ `add r32, r/m32` (`0x03`) với ModR/M flip. Tiêu chí: cặp tương đương semantic và cùng số byte (không cần relocation fix).

  4. `_validate_output` chạy parse + basic sanity check; nếu fail thì fallback file gốc.
  5. Kết quả được cache vào `rewriter_output/<orig_name>.CR`. Nếu arm CR được tái kích hoạt ([arm.py:247-277 — ArmCR](../MAB-malware/core/arm.py#L247-L277)), nó chỉ copy file `.CR` đã có thay vì chạy IDA lại — CR rất đắt (cần IDA + timeout dài).
* **Affected features:** F2 (Section Hash), F9 (Code Sequence) — "rule-based signatures dùng byte trong `.text`" sẽ mismatch sau CR.
* **Không gian & Khả năng đảo ngược:** **Problem-space nghiêm ngặt.** CR là action **code-rewriting preserving** duy nhất trong 3 paper đã phân tích (OBFU-mal, DQEAF chỉ thêm/xóa). Vì 4 transform đều là equivalent rewrites (cùng length, bảo toàn liveness, bảo toàn CFG semantic), file PE giữ nguyên chức năng. Đây là lý do Table 2 liệt kê CR chạm F9 (Code Sequence) — tấn công trực tiếp vào static byte-signature thay vì chỉ thay đổi metadata quanh code.

---

## 9–13. Micro-actions: OA1, SP1, SA1, SR1, CP1

Paper Section 4.2.1: "If an action 𝑎 changes feature set 𝐹 = {𝑓1, ..., 𝑓𝑘}, then another action that changes only a subset of 𝐹 is a micro-action of 𝑎." Micro-action được sinh ra ở **Action Minimization phase** để thay macro-action, giảm feature delta.

| Abbr | Canonical | Vị trí | Budget | Implementation |
|---|---|---|---|---|
| **OA1** | `OVERLAY_APPEND` (micro) | EOF | **1 byte** | [arm.py:105-152](../MAB-malware/core/arm.py#L105-L152), chỉ set `content = bytes([1])`. Chỉ chạm F1 (File Hash), không chạm F10. |
| **SP1** | `SLACK_SPACE_FILL` (micro) | slack của section random | **1 byte** | [arm.py:310-434](../MAB-malware/core/arm.py#L310-L434) với `content = bytes([1])`, tắt branch extend-content. Chỉ chạm F2, không chạm F5. |
| **SA1** | `SECTION_ADD` (micro) | section table + raw | **1 byte content** | [arm.py:579-722](../MAB-malware/core/arm.py#L579-L722) với `content = bytes([1])`. Chỉ chạm F3 (Section Count), không chạm F10. |
| **SR1** | `SECTION_RENAME` (micro) | section Name field | **1 ký tự** | [arm.py:505-514 — randomly_change_one_byte](../MAB-malware/core/arm.py#L505-L514): lấy `old_name`, flip đúng 1 ký tự bằng `random.choice(string.ascii_lowercase)`, loop đến khi `new_name != old_name`. Chỉ chạm F4 (Section Name) ở mức tối thiểu. |
| **CP1** | `SLACK_SPACE_FILL` của `.text` (micro) | slack của section **code** | **1 byte** | [arm.py:436-484 — ArmCP1](../MAB-malware/core/arm.py#L436-L484). Tìm section có tên `.text` (`section.Name[:5] == '.text'`), append đúng 1 byte vào slack của nó. Chạm F2 (Section Hash) **và** F9 (Code Sequence hash/signature) — vì code section hash thay đổi. Đây là micro-action được thiết kế để chạm **F9** ở mức byte tối thiểu mà CR cần toàn bộ IDA pipeline. |

**Tất cả 5 micro đều problem-space, file PE chạy được** (1 byte vào slack / EOF / rename 1 char / header section mới với 1 byte content — đều không chạm vùng instruction đang chạy).

---

## Bảng ánh xạ tóm tắt — MAB-malware

| Abbr | Paper name | Canonical | Tier | Affected features (Table 2) | Operation |
|---|---|---|---|---|---|
| OA | Overlay Append | `OVERLAY_APPEND` | Macro | F1, F10 | Append benign content vào EOF |
| SP | Section Append | `SLACK_SPACE_FILL` / `SECTION_APPEND_BYTES` | Macro | F2, F5 | Fill slack của section random |
| SA | Section Add | `SECTION_ADD` | Macro | F3, F10 | Thêm section header mới + raw content benign |
| SR | Section Rename | `SECTION_RENAME` | Macro | F4 | Đổi tên = tên từ pool benign |
| RC | Remove Certificate | `REMOVE_SIGNATURE` | Macro | F8 | Zero-out certificate blob + unlink DataDir |
| RD | Remove Debug | `REMOVE_DEBUG` | Macro | F6 | Zero-out PDB segment + unlink DataDir |
| BC | Break Checksum | `BREAK_CHECKSUM` | Macro | F7 | `OptionalHeader.CheckSum = 0` |
| CR | Code Randomization | `CODE_RANDOMIZE` (+ `CFG_EDGE_REDIVIDE`) | Macro | F2, F9 | IDA + Capstone: reg swap / prologue reorder / bbl reorder / atomic substitution |
| OA1 | Overlay Append 1B | `OVERLAY_APPEND` | Micro | F1 | 1 byte vào overlay |
| SP1 | Section Append 1B | `SLACK_SPACE_FILL` | Micro | F2 | 1 byte vào slack section |
| SA1 | Section Add 1B | `SECTION_ADD` | Micro | F3 | Section mới với 1 byte content |
| SR1 | Section Rename 1B | `SECTION_RENAME` | Micro | F4 | Flip 1 ký tự trong section name |
| CP1 | Code Section Append 1B | `SLACK_SPACE_FILL` của `.text` | Micro | F2, F9 | 1 byte vào slack của `.text` |

## Ghi chú quan trọng — MAB-malware

1. **Micro-action là đóng góp kiến trúc chính**: đây là lớp action mà OBFU-mal, DQEAF, gym-malware không có. Sau khi RL tìm ra AE bằng macro, minimizer thay mỗi macro bằng micro "affect ⊂ macro's feature set" rồi re-check; reward chỉ được gán cho micro essential → bandit học được chính xác feature nào quan trọng.
2. **Content pool khác biệt**: `Utils.get_random_content()` lấy **chunk từ binary sạch** (tên section, content), không phải random bytes như DQEAF. Điều này giúp data distribution (F10) trông "benign" theo thống kê byte-histogram của detector. Đồng thời cho phép **tái sử dụng content-action pair** qua Thompson sampling — ý niệm "slot machine".
3. **SP thực chất là slack-fill, không phải append section** — giống mismatch đã quan sát trong OBFU-mal. `Section Append` ở đây = `SECTION_APPEND_BYTES` / `SLACK_SPACE_FILL`, không phải `SECTION_ADD`.
4. **CR là action code-level duy nhất trong cả 3 paper đã phân tích (OBFU-mal/DQEAF/MAB-malware)**, và là action đắt nhất (cần IDA headless, timeout 900s). Nó là action duy nhất tác động đến **F9 (Code Sequence)** mà không phá semantic. Map vào canonical: `CODE_RANDOMIZE` là fit chính, `SEMANTIC_NOP_INJECT` không chính xác (CR không inject NOP, mà swap equivalent instructions), `CFG_EDGE_REDIVIDE` áp cho sub-transform basic_block_reordering.
5. **Characteristics của SA luôn là `0xE0000020`** = `CNT_CODE | MEM_EXECUTE | MEM_READ | MEM_WRITE` ([arm.py:681](../MAB-malware/core/arm.py#L681)). Cứng, không random như DQEAF. Section mới có thể bị flag là RWX bởi một số detector — trade-off thú vị khác nhau giữa detector-specific features.
6. **Fallback an toàn**: mỗi arm luôn chạy `try_parse_pe(output_path)` sau transform; nếu không parse được thì `cp -p input output` (no-op). Giảm rủi ro corrupt file.
7. Canonical action **không có** trong MAB-malware: `HEADER_PERTURB`, `DOS_HEADER_*`, `CONTENT_SHIFT`, `PACKING`/`UPX_*`, `XOR_ENCRYPTION`, `DROPPER`, `IMPORTS_APPEND`/`IAT_INJECTION`, `TIMESTAMP`, `NEW_ENTRYPOINT`, `CODE_REWRITE_DIRECT`, `CODE_REWRITE_MINIMAL`, `CODE_TRANSLATION`, `BYTECODE_API_HIJACKING`. Đáng chú ý MAB-malware **không có Imports Append** — khác biệt với OBFU-mal/DQEAF.

---
---

# AIMED-RL — Phân tích & Ánh xạ Action

Nguồn: [AIMED_RL.txt](../FAME-master/FAME-master/AIMED_RL.txt) (Labaca-Castro et al., "AIMED-RL: Exploring Adversarial Malware Examples with Reinforcement Learning") + [FAME-master/FAME-master/data/manipulate.py](../FAME-master/FAME-master/data/manipulate.py) (action implementation) + [FAME-master/FAME-master/src/rl.py](../FAME-master/FAME-master/src/rl.py) (RL env) + [FAME-master/FAME-master/src/functions.py](../FAME-master/FAME-master/src/functions.py) (rec_mod_files pipeline).

**Bối cảnh:**
- AIMED-RL là 1 phần của repo FAME (chứa nhiều model khác như GP, defense, v.v.); phần RL được implement trong `src/rl.py` và `data/manipulate.py`. Module `data/manipulate.py` **kế thừa trực tiếp từ [gym-malware](https://github.com/endgameinc/gym-malware) (Anderson et al. 2018)** — comment header `# Source: https://github.com/endgameinc/gym-malware` ở dòng 1.
- Paper AIMED-RL không định nghĩa action mới; đóng góp của paper là ở: (a) **agent Distributional Double DQN + Noisy Nets**, (b) reward kết hợp detection + similarity + distance với weight scheme `Standard`/`Incremental`, (c) **penalty cho perturbation lặp**, (d) giới hạn 5 perturbation/episode, (e) integrity check sau khi sinh AE.
- Action space = **10 action của gym-malware**, định nghĩa trong `ACTION_TABLE` ở [manipulate.py:289-301](../FAME-master/FAME-master/data/manipulate.py#L289-L301). Paper Section 3.2 liệt kê i)–x) trùng khớp với list này, **loại bỏ** `identity` và `create_new_entry` vì "technical problems".
- Toàn bộ action đều **problem-space** — `rec_mod_files()` apply `MalwareManipulator` method lên bytez, rồi `build_bytes()` gọi `lief.PE.Builder` rebuild import table + patch + write ra file `.exe`. Paper nhấn mạnh AIMED-RL "avoid feature-space" và "verify integrity by executing in a protected environment" (Section 4.1).

---

## 1. overlay_append

* **Hành động chuẩn hóa:** `OVERLAY_APPEND`
* **Tên gốc:** "overlay_append — Appends a sequence of bytes at the end of the PE file (overlay); length and entropy are random" (paper Section 3.2, action i)
* **Thao tác:** Thêm (EOF)
* **Chi tiết Triển khai:** [manipulate.py:52-61](../FAME-master/FAME-master/data/manipulate.py#L52-L61):
  ```python
  L = 2 ** random.randint(5, 8)        # 32..256 byte
  upper = random.randrange(256)
  return self.bytez + bytes([random.randint(0, upper) for _ in range(L)])
  ```
  * Vị trí: nối thẳng vào `self.bytez` → overlay.
  * Nội dung: byte random với upper bound chọn ngẫu nhiên (`upper=0` → toàn 0; `upper=126` → printable ASCII; `upper=255` → byte bất kỳ). Paper ghi rõ "length and entropy are random".
  * Ngân sách: 32–256 byte.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Append vào overlay, PE chạy được.

---

## 2. imports_append

* **Hành động chuẩn hóa:** `IMPORTS_APPEND` (∈ `IAT_INJECTION`)
* **Tên gốc:** "imports_append — Adds an unused function to the import table in the data directory. The function is chosen randomly from a predefined list of DLL imports" (paper Section 3.2, action ii)
* **Thao tác:** Thêm (IAT entry)
* **Chi tiết Triển khai:** [manipulate.py:63-87](../FAME-master/FAME-master/data/manipulate.py#L63-L87):
  ```python
  libname = random.choice(list(COMMON_IMPORTS.keys()))
  funcname = random.choice(list(COMMON_IMPORTS[libname]))
  lib = binary.add_library(libname)  # nếu chưa có
  lib.add_entry(funcname)
  self.bytez = self.__binary_to_bytez(binary, imports=True)
  ```
  * `COMMON_IMPORTS` load từ [data/small_dll_imports.json](../FAME-master/FAME-master/data/small_dll_imports.json) — **danh sách DLL + function thật** (khác DQEAF dùng random ASCII). Paper gọi là "predefined list of DLL imports".
  * Build qua `lief.PE.Builder` với `build_imports=True` và `patch_imports=True` — có nghĩa LIEF rebuild IAT vào một section mới (`.l1`) và patch trampoline trong import table cũ, bảo toàn cả import cũ lẫn mới ([manipulate.py:34-50](../FAME-master/FAME-master/data/manipulate.py#L34-L50)).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Vì DLL/func là thật, loader resolve được → file chạy được trên Windows thật (**khác DQEAF**). Function không bao giờ được call → không phá behavior.

---

## 3. section_rename

* **Hành động chuẩn hóa:** `SECTION_RENAME`
* **Tên gốc:** "section_rename — Manipulates an existing section name. For all section perturbations the section name is chosen at random from a list of known benign section names" (paper Section 3.2, action iii)
* **Thao tác:** Sửa
* **Chi tiết Triển khai:** [manipulate.py:89-98](../FAME-master/FAME-master/data/manipulate.py#L89-L98):
  ```python
  targeted_section = random.choice(binary.sections)
  targeted_section.name = random.choice(COMMON_SECTION_NAMES)[:7]
  ```
  * `COMMON_SECTION_NAMES` load từ [data/section_names.txt](../FAME-master/FAME-master/data/section_names.txt) — tên section thật từ binary sạch.
  * Cắt 7 ký tự (comment: "actual version of lief not allowing 8 chars?").
* **Không gian & Khả năng đảo ngược:** **Problem-space.**

---

## 4. section_add

* **Hành động chuẩn hóa:** `SECTION_ADD`
* **Tên gốc:** "section_add — Creates a new unused section in the section table" (paper Section 3.2, action iv)
* **Thao tác:** Thêm (section mới)
* **Chi tiết Triển khai:** [manipulate.py:100-129](../FAME-master/FAME-master/data/manipulate.py#L100-L129):
  ```python
  new_section = lief.PE.Section(
      "".join(chr(random.randrange(ord('.'), ord('z'))) for _ in range(6)))
  upper = random.randrange(256)
  L = 2 ** random.randint(5, 8)   # 32..256
  new_section.content = [random.randint(0, upper) for _ in range(L)]
  new_section.virtual_address = max(s.virtual_address + s.size for s in binary.sections)
  binary.add_section(new_section, random.choice([
      BSS, DATA, EXPORT, IDATA, RELOCATION, RESOURCE, TEXT, TLS_, UNKNOWN
  ]))
  ```
  * Tên section: 6 ký tự random trong khoảng `.`..`z`.
  * Content: 32–256 byte random (khác DQEAF 128–1024).
  * Virtual address: ép = `max(end of existing sections)` để không overlap.
  * Section type: sample ngẫu nhiên từ 9 loại (thêm `DATA`, `EXPORT` so với DQEAF 7 loại).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Section không bao giờ được EP trỏ tới → file chạy được.

---

## 5. section_append

* **Hành động chuẩn hóa:** `SECTION_APPEND_BYTES` / `SLACK_SPACE_FILL`
* **Tên gốc:** "section_append — Appends bytes at the end of a section. The length and entropy of the injected bytes is again chosen at random" (paper Section 3.2, action v)
* **Thao tác:** Thêm (vào slack)
* **Chi tiết Triển khai:** [manipulate.py:131-146](../FAME-master/FAME-master/data/manipulate.py#L131-L146):
  ```python
  targeted_section = random.choice(binary.sections)
  L = 2 ** random.randint(5, 8)
  available_size = targeted_section.size - len(targeted_section.content)
  if L > available_size: L = available_size
  targeted_section.content = targeted_section.content + \
      [random.randint(0, upper) for _ in range(L)]
  ```
  * Giống hệt logic `SectionAppend` của OBFU-mal/MAB — fill slack của section random.
  * Cùng mismatch paper/code: paper nói "append bytes at the end of a section" (mơ hồ), code fill slack (không thêm raw size).
* **Không gian & Khả năng đảo ngược:** **Problem-space.**

---

## 6. upx_pack

* **Hành động chuẩn hóa:** `UPX_PACK` / `PACKING`
* **Tên gốc:** "upx_pack — Uses the UPX packer to pack the whole PE file. Note that the compression level (between 1 and 9) is also chosen at random" (paper Section 3.2, action vi)
* **Thao tác:** Nén toàn file
* **Chi tiết Triển khai:** [manipulate.py:184-224](../FAME-master/FAME-master/data/manipulate.py#L184-L224):
  * Dump bytez ra temp file, gọi `upx` subprocess với:
    ```python
    options = ['--force', '--overlay=copy']
    options += ['-{}'.format(random.randint(1, 9))]
    options += ['--compress-exports={}'.format(random.randint(0, 1))]
    options += ['--compress-icons={}'.format(random.randint(0, 3))]
    options += ['--compress-resources={}'.format(random.randint(0, 1))]
    options += ['--strip-relocs={}'.format(random.randint(0, 1))]
    ```
  * Giống hệt OBFU-mal `UPXPack` (OBFU-mal kế thừa style này từ gym-malware).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** UPX output là PE self-unpacking hợp lệ.

---

## 7. upx_unpack  *— khác biệt so với các paper khác*

* **Hành động chuẩn hóa:** `UPX_UNPACK`
* **Tên gốc:** "upx_unpack — Unpacks the file using the UPX packer" (paper Section 3.2, action vii)
* **Thao tác:** Giải nén (chỉ khi file đã được pack trước đó)
* **Chi tiết Triển khai:** [manipulate.py:226-246](../FAME-master/FAME-master/data/manipulate.py#L226-L246):
  ```python
  subprocess.call(['upx', tmpfilename, '-d', '-o', tmpfilename + '_unpacked'])
  ```
  * Gọi `upx -d` (decompress). Nếu file không phải UPX-packed → `retcode != 0`, giữ nguyên bytez (no-op).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Đây là action **duy nhất trong 4 paper đã phân tích** có "inverse": gỡ packing. Lý do tồn tại: một số detector flag UPX-packed là malicious → agent học được gỡ UPX khi file gốc đã pack là chiến thuật né. Canonical list của user có sẵn `UPX_UNPACK` cho trường hợp này.

---

## 8. remove_signature

* **Hành động chuẩn hóa:** `REMOVE_SIGNATURE`
* **Tên gốc:** "remove_signature — Removes the signer information in the certificate table of the data directory" (paper Section 3.2, action viii)
* **Thao tác:** Xóa (unlink)
* **Chi tiết Triển khai:** [manipulate.py:248-263](../FAME-master/FAME-master/data/manipulate.py#L248-L263):
  ```python
  if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
      e.rva = 0
      e.size = 0
  ```
  * Chỉ unlink pointer (giống OBFU-mal, khác MAB-malware zero-out + DQEAF xóa signature object).
* **Không gian & Khả năng đảo ngược:** **Problem-space.**

---

## 9. remove_debug

* **Hành động chuẩn hóa:** `REMOVE_DEBUG`
* **Tên gốc:** "remove_debug — Manipulates the debug information in the data directory" (paper Section 3.2, action ix)
* **Thao tác:** Xóa (unlink)
* **Chi tiết Triển khai:** [manipulate.py:265-280](../FAME-master/FAME-master/data/manipulate.py#L265-L280): set `DataDir[DEBUG].rva = 0, .size = 0`. Chỉ unlink (giống OBFU-mal).
* **Không gian & Khả năng đảo ngược:** **Problem-space.**

---

## 10. break_optional_header_checksum

* **Hành động chuẩn hóa:** `BREAK_CHECKSUM`
* **Tên gốc:** "break_optional_header_checksum — Modifies and thus breaks the optional header checksum by setting it to 0" (paper Section 3.2, action x)
* **Thao tác:** Sửa
* **Chi tiết Triển khai:** [manipulate.py:282-286](../FAME-master/FAME-master/data/manipulate.py#L282-L286):
  ```python
  binary.optional_header.checksum = 0
  ```
* **Không gian & Khả năng đảo ngược:** **Problem-space.**

---

## *(Bị loại bỏ)*: `create_new_entry`

* **Tên gốc:** "create_new_entry" — comment trong code: "generates often entry point errors" ([manipulate.py:300](../FAME-master/FAME-master/data/manipulate.py#L300), commented-out trong `ACTION_TABLE`).
* **Canonical:** `NEW_ENTRYPOINT` (không được dùng trong AIMED-RL).
* **Lý do loại:** Paper Section 3.2 cuối mục Actions: "with the exception of identity and create new entry point, which were left out because of technical problems".
* **Chi tiết Triển khai** (nếu được bật) ở [manipulate.py:152-182](../FAME-master/FAME-master/data/manipulate.py#L152-L182): tạo section mới chứa stub `push [old_EP+0x10000]; ret` (opcode `0x68 <imm32> 0xC3`), rồi sửa `optional_header.addressof_entrypoint` trỏ vào section mới. Comment thừa nhận "may have a few technical issues with it (not accounting for relocations)". Đây là lý do bị disable.

---

## Bảng ánh xạ tóm tắt — AIMED-RL

| Paper name | Canonical | Thao tác | Ngân sách |
|---|---|---|---|
| overlay_append | `OVERLAY_APPEND` | Thêm EOF | 32–256 byte random |
| imports_append | `IMPORTS_APPEND` / `IAT_INJECTION` | Thêm IAT entry | 1 entry từ pool DLL thật |
| section_rename | `SECTION_RENAME` | Sửa | Tên từ pool benign, 7 ký tự |
| section_add | `SECTION_ADD` | Thêm section | 32–256 byte random, 1 trong 9 section type |
| section_append | `SLACK_SPACE_FILL` / `SECTION_APPEND_BYTES` | Thêm slack | ≤32–256 byte |
| upx_pack | `UPX_PACK` / `PACKING` | Nén | Toàn file, level 1–9 random |
| **upx_unpack** | **`UPX_UNPACK`** | **Giải nén** | **Toàn file, no-op nếu không UPX-packed** |
| remove_signature | `REMOVE_SIGNATURE` | Unlink `DataDir[CERT]` | 1 pointer |
| remove_debug | `REMOVE_DEBUG` | Unlink `DataDir[DEBUG]` | 1 pointer |
| break_optional_header_checksum | `BREAK_CHECKSUM` | `CheckSum = 0` | 4 byte |
| *(disabled)* create_new_entry | `NEW_ENTRYPOINT` | — | — |

## Ghi chú quan trọng — AIMED-RL

1. **Action space = gym-malware**: AIMED-RL không thêm action mới; [data/manipulate.py](../FAME-master/FAME-master/data/manipulate.py) ghi rõ `# Source: https://github.com/endgameinc/gym-malware`. So sánh với OBFU-mal: OBFU-mal bắt đầu từ cùng gốc nhưng thêm Darkarmour XOR EL1/2/3 và UPX pack; AIMED-RL thêm **upx_unpack** và bỏ **create_new_entry**.
2. **UPX_UNPACK là duy nhất trong 4 paper đã phân tích**. Action này chỉ có ý nghĩa nếu file đầu vào đã UPX-packed; ngược lại subprocess trả retcode khác 0 → no-op. Đây là action "inverse" thể hiện triết lý "decrease entropy" để né detector coi UPX = malicious.
3. **`create_new_entry` bị loại** vì không account được relocation khi redirect EP — code `struct.pack("<I", entry_point + 0x10000)` chỉ hoạt động trên PE không có base relocation hoặc load tại preferred base. Đây là ví dụ thực tế của việc canonical action `NEW_ENTRYPOINT` khó triển khai preserving-functionality.
4. **Integrity verification**: paper Section 4 nói rõ integrity verify bằng "executing the adversarial example in a protected environment". Code [functions.py:164-188 — rec_mod_files](../FAME-master/FAME-master/src/functions.py#L164-L188) apply action sequence recursive rồi gọi `build_bytes()` ([functions.py:139-161](../FAME-master/FAME-master/src/functions.py#L139-L161)) — nếu `lief.PE.Builder` throw exception (PE corrupt sau action) → trả về `None` và `rl.step` raise `PE Manipulation Errors` ([rl.py:94-97](../FAME-master/FAME-master/src/rl.py#L94-L97)). Đây là safety layer khác nhau so với MAB (try_parse_pe + cp fallback) và DQEAF (ProcessPool timeout).
5. **Giới hạn 5 perturbation/episode** (paper Section 3.2) — khác biệt đáng kể với OBFU-mal/Anderson dùng 10 turn. Paper argue "the length of the perturbation sequence proved to be less important than the order of the injected perturbations" (trích [5] stochastic AIMED).
6. **Penalty cho perturbation lặp**: [rl.py:221-244](../FAME-master/FAME-master/src/rl.py#L221-L244) — nếu 1 action xuất hiện >2 lần trong `actions_taken`, reward × 0.6; >1 lần → × 0.8. Đây là cơ chế nhắm tăng **diversity** của sequence, không liên quan trực tiếp action space nhưng là đóng góp chính của AIMED-RL.
7. **`section_add` ở đây ép `virtual_address = max(end)`**, khác DQEAF (để LIEF tự compute) và MAB (thủ công tính). Đây là điểm có thể gây conflict nếu section cuối cùng đã align đến giới hạn.
8. Canonical action **không có** trong AIMED-RL: `HEADER_PERTURB`, `SLACK_SPACE_FILL` (explicit — chỉ có qua section_append), `DOS_HEADER_*`, `CONTENT_SHIFT`, `XOR_ENCRYPTION`, `DROPPER`, `TIMESTAMP`, `CODE_REWRITE_*`, `CODE_TRANSLATION`, `CODE_RANDOMIZE`, `CFG_*`, `SEMANTIC_NOP_INJECT`, `BYTECODE_API_HIJACKING`. `NEW_ENTRYPOINT` **có implementation nhưng bị disable**.

---
---

# FAME — Phân tích & Ánh xạ Action

Nguồn: [FAME-master/README.md](../FAME-master/FAME-master/README.md) (Labaca-Castro et al., "Machine Learning under Malware Attack", Springer 2023) + [FAME-master/FAME-master/data/manipulate.py](../FAME-master/FAME-master/data/manipulate.py) (action implementation).

**FAME = Framework for Adversarial Malware Evaluation**, hợp nhất 3 module tấn công: **ARMED** (random), **AIMED** (GP + RL), **GAME-UP** (Universal Adversarial Perturbations). Không đề xuất action mới — **action space là port trực tiếp từ gym-malware của Endgame/Anderson et al. 2018**: file [manipulate.py:1](../FAME-master/FAME-master/data/manipulate.py#L1) ghi rõ `# Source: https://github.com/endgameinc/gym-malware`. FAME đóng góp ở lớp **orchestration + validation**: agent (GP/RL/Random) chọn chuỗi action, mỗi action được verify bằng functional test qua Cuckoo / VirusTotal / MetaDefender / Hybrid Analysis sandbox ([functions.py:244-480](../FAME-master/FAME-master/src/functions.py#L244-L480)).

**Action space — Table `ACTION_TABLE`** ([manipulate.py:289-301](../FAME-master/FAME-master/data/manipulate.py#L289-L301)):
```python
ACTION_TABLE = {
    'overlay_append': ...,                  # 0
    'imports_append': ...,                  # 1
    'section_rename': ...,                  # 2
    'section_add': ...,                     # 3
    'section_append': ...,                  # 4
    'remove_signature': ...,                # 5
    'remove_debug': ...,                    # 6
    'upx_pack': ...,                        # 7
    'upx_unpack': ...,                      # 8
    'break_optional_header_checksum': ...,  # 9
#   'create_new_entry': ...,                # disabled: "generates often entry point errors"
}
```

10 action active + 1 action implemented-nhưng-disabled. Tất cả thuộc class [`MalwareManipulator`](../FAME-master/FAME-master/data/manipulate.py#L25), dùng LIEF cho PE action và subprocess cho UPX. **Tất cả problem-space.**

Content pool:
- [`section_names.txt`](../FAME-master/FAME-master/data/section_names.txt): pool tên section thật (`.text`, `.rsrc`, `.reloc`, `.data`, `.rdata`, `.idata`, `.tls`, `.brdata`, `.bss`, `.pdata`, ...).
- [`small_dll_imports.json`](../FAME-master/FAME-master/data/small_dll_imports.json): pool DLL/function **thật** từ `ADVAPI32.DLL` / `KERNEL32.DLL` / ... Ví dụ `ADVAPI32.DLL` → `CryptSetProvParam`, `RegQueryInfoKeyW`, `AddUsersToEncryptedFileEx`, ...

---

## 1. overlay_append

* **Hành động chuẩn hóa:** `OVERLAY_APPEND`
* **Tên gốc:** `overlay_append` ([manipulate.py:52-61](../FAME-master/FAME-master/data/manipulate.py#L52-L61))
* **Thao tác:** Thêm (EOF)
* **Chi tiết Triển khai:**
  ```python
  L = 2**random.randint(5, 8)                  # 32..256 byte
  upper = random.randrange(256)
  return self.bytez + bytes([random.randint(0, upper) for _ in range(L)])
  ```
  * Vị trí: overlay (sau section cuối).
  * Content: byte random bounded bởi `upper` ∈ [0, 255]. Comment trong code giải thích: `upper=0` → all zeros, `upper=126` → "printable ascii", `upper=255` → any character. Random upper mỗi lần.
  * Ngân sách: **32–256 byte / lần** (giống OBFU-mal).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** File chạy được.

---

## 2. imports_append

* **Hành động chuẩn hóa:** `IMPORTS_APPEND` (∈ `IAT_INJECTION`)
* **Tên gốc:** `imports_append` ([manipulate.py:63-87](../FAME-master/FAME-master/data/manipulate.py#L63-L87))
* **Thao tác:** Thêm (IAT entry)
* **Chi tiết Triển khai:**
  * Chọn `libname`/`funcname` random từ `COMMON_IMPORTS` (= `small_dll_imports.json`). Tìm DLL trong imports hiện có; nếu không có thì `binary.add_library(libname)`, rồi `lib.add_entry(funcname)` nếu chưa tồn tại.
  * Rebuild bằng `__binary_to_bytez(binary, imports=True)` — LIEF `Builder` dựng IAT trong section mới và patch IAT gốc bằng trampoline ([manipulate.py:34-50](../FAME-master/FAME-master/data/manipulate.py#L34-L50)):
    ```python
    builder.build_imports(imports)   # rebuild IAT in another section
    builder.patch_imports(imports)   # patch orig. import table with trampolines
    ```
  * **Khác DQEAF**: tên DLL/function là **thật** (từ pool `small_dll_imports.json`) → binary chạy được trên Windows thật. Khác OBFU-mal: whitelist FAME lớn hơn (pool mấy chục DLL, không chỉ 5 DLL core).
  * Ngân sách: 1 DLL + 1 function / lần.
* **Không gian & Khả năng đảo ngược:** **Problem-space, functionally valid.** Vì DLL tên thật, loader resolve được. Trampoline patching của LIEF đảm bảo IAT gốc vẫn work sau khi relocate.

---

## 3. section_rename

* **Hành động chuẩn hóa:** `SECTION_RENAME`
* **Tên gốc:** `section_rename` ([manipulate.py:89-98](../FAME-master/FAME-master/data/manipulate.py#L89-L98))
* **Thao tác:** Sửa (field Name)
* **Chi tiết Triển khai:**
  ```python
  targeted_section = random.choice(binary.sections)
  targeted_section.name = random.choice(COMMON_SECTION_NAMES)[:7]
  ```
  * Chọn section random, đổi tên thành tên random từ `section_names.txt` (pool >50 tên thật). Cắt `[:7]` vì "actual version of lief not allowing 8 chars" (comment trong code — LIEF có bug không cho set 8 byte Name).
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Giống OBFU-mal/MAB, file chạy bình thường.

---

## 4. section_add

* **Hành động chuẩn hóa:** `SECTION_ADD`
* **Tên gốc:** `section_add` ([manipulate.py:100-129](../FAME-master/FAME-master/data/manipulate.py#L100-L129))
* **Thao tác:** Thêm (section mới thật sự)
* **Chi tiết Triển khai:**
  ```python
  new_section = lief.PE.Section(
      "".join(chr(random.randrange(ord('.'), ord('z'))) for _ in range(6)))
  upper = random.randrange(256)
  L = 2**random.randint(5, 8)              # 32..256
  new_section.content = [random.randint(0, upper) for _ in range(L)]
  new_section.virtual_address = max([s.virtual_address + s.size for s in binary.sections])
  binary.add_section(new_section, random.choice([
      BSS, DATA, EXPORT, IDATA, RELOCATION, RESOURCE, TEXT, TLS_, UNKNOWN
  ]))
  ```
  * Vị trí: append vào section table. VA = cuối của section cuối cùng.
  * Tên: **6 ký tự ASCII random** trong dải `. .. z` (không có `.` prefix — tên dạng "Abc#4h" chứ không phải ".abc4h"). Đây là một khác biệt nhỏ so với DQEAF (có prefix `.`).
  * Content: **32–256 byte random** với `upper` bounded.
  * Section type: chọn random từ 9 type (BSS, DATA, EXPORT, IDATA, RELOCATION, RESOURCE, TEXT, TLS_, UNKNOWN) → LIEF sẽ set `Characteristics` tương ứng. Giống DQEAF nhưng thêm DATA + EXPORT, bỏ TLS_callback rủi ro.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** LIEF rebuild cập nhật `SizeOfImage`, `NumberOfSections`. Section mới không được EP trỏ tới → file vẫn chạy.

---

## 5. section_append *— lại là slack fill*

* **Hành động chuẩn hóa:** `SECTION_APPEND_BYTES` / `SLACK_SPACE_FILL`
* **Tên gốc:** `section_append` ([manipulate.py:131-146](../FAME-master/FAME-master/data/manipulate.py#L131-L146))
* **Thao tác:** Thêm (vào slack)
* **Chi tiết Triển khai:**
  ```python
  targeted_section = random.choice(binary.sections)
  L = 2**random.randint(5, 8)
  available_size = targeted_section.size - len(targeted_section.content)
  if L > available_size:
      L = available_size
  upper = random.randrange(256)
  targeted_section.content = targeted_section.content + \
      [random.randint(0, upper) for _ in range(L)]
  ```
  * Comment trong code: "append to a section (changes size and entropy)" — nhưng thực tế là **fill slack**: `available_size = section.size - len(content)`.
  * Giống mismatch naming đã thấy ở OBFU-mal và MAB-malware. Cả 3 framework đều có cùng mẫu: "section_append" trong paper nghe như "thêm byte vào raw section", nhưng code thì fill slack trong phạm vi `section.size` có sẵn.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** Không vượt quá virtual size nên LIEF không cần relocate.

---

## 6. remove_signature

* **Hành động chuẩn hóa:** `REMOVE_SIGNATURE`
* **Tên gốc:** `remove_signature` ([manipulate.py:248-263](../FAME-master/FAME-master/data/manipulate.py#L248-L263))
* **Thao tác:** Xóa (unlink pointer)
* **Chi tiết Triển khai:**
  ```python
  if binary.has_signature:
      for i, e in enumerate(binary.data_directories):
          if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
              break
      e.rva = 0
      e.size = 0
  ```
  * Chỉ unlink `DataDir[CERTIFICATE_TABLE]`. **Không** xóa byte chứng chỉ trong overlay, **không** xóa signature object — giống OBFU-mal, yếu hơn DQEAF/MAB.
* **Không gian & Khả năng đảo ngược:** **Problem-space.**

---

## 7. remove_debug

* **Hành động chuẩn hóa:** `REMOVE_DEBUG`
* **Tên gốc:** `remove_debug` ([manipulate.py:265-280](../FAME-master/FAME-master/data/manipulate.py#L265-L280))
* **Thao tác:** Xóa (unlink pointer)
* **Chi tiết Triển khai:** Gần giống `remove_signature`, unlink `DataDir[DEBUG]` (set rva=size=0). Không xóa PDB segment thật (khác MAB-malware có `zero_out_file_content`).
* **Không gian & Khả năng đảo ngược:** **Problem-space.**

---

## 8. upx_pack

* **Hành động chuẩn hóa:** `UPX_PACK` / `PACKING`
* **Tên gốc:** `upx_pack` ([manipulate.py:184-224](../FAME-master/FAME-master/data/manipulate.py#L184-L224))
* **Thao tác:** Nén toàn file
* **Chi tiết Triển khai:**
  ```python
  options = ['--force', '--overlay=copy']
  options += ['-{}'.format(random.randint(1, 9))]           # level
  options += ['--compress-exports={}'.format(random.randint(0, 1))]
  options += ['--compress-icons={}'.format(random.randint(0, 3))]
  options += ['--compress-resources={}'.format(random.randint(0, 1))]
  options += ['--strip-relocs={}'.format(random.randint(0, 1))]
  subprocess.call(['upx'] + options + [tmpfilename, '-o', tmpfilename + '_packed'], ...)
  ```
  * **Giống OBFU-mal 1:1** (OBFU-mal cũng copy từ gym-malware).
  * Ngân sách: toàn file.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** UPX stub self-unpack → file chạy được.

---

## 9. upx_unpack *— action independent của FAME/gym-malware*

* **Hành động chuẩn hóa:** `UPX_UNPACK`
* **Tên gốc:** `upx_unpack` ([manipulate.py:226-246](../FAME-master/FAME-master/data/manipulate.py#L226-L246))
* **Thao tác:** Gỡ nén toàn file
* **Chi tiết Triển khai:**
  ```python
  subprocess.call(['upx', tmpfilename, '-d', '-o', tmpfilename + '_unpacked'], ...)
  ```
  * Gọi `upx -d` để decompress. **Chỉ có tác dụng nếu malware gốc đang bị UPX-pack** (không then-fail, trả về `bytez` gốc nếu unpack fail).
  * **Đây là action duy nhất có "inverse" trong tất cả paper đã phân tích** — các agent trước chỉ thêm obfuscation, không gỡ. Lý do: nhiều malware family (như packed Zbot, Locker) sẵn bị UPX-pack; nhiều detector flag UPX signature → unpack có thể là action evasive.
* **Không gian & Khả năng đảo ngược:** **Problem-space.** File sau unpack là PE gốc, chạy được (nếu packer không custom).

---

## 10. break_optional_header_checksum

* **Hành động chuẩn hóa:** `BREAK_CHECKSUM`
* **Tên gốc:** `break_optional_header_checksum` ([manipulate.py:282-286](../FAME-master/FAME-master/data/manipulate.py#L282-L286))
* **Thao tác:** Sửa
* **Chi tiết Triển khai:**
  ```python
  binary.optional_header.checksum = 0
  ```
  Giống OBFU-mal/MAB-malware. Set về 0.
* **Không gian & Khả năng đảo ngược:** **Problem-space.**

---

## 11. create_new_entry *— implemented nhưng DISABLED*

* **Hành động chuẩn hóa:** `NEW_ENTRYPOINT` (+ `SECTION_ADD` + `CODE_REWRITE_MINIMAL`)
* **Tên gốc:** `create_new_entry` ([manipulate.py:152-182](../FAME-master/FAME-master/data/manipulate.py#L152-L182))
* **Thao tác:** Thêm section + sửa EP
* **Chi tiết Triển khai:**
  ```python
  entry_point = binary.optional_header.addressof_entrypoint
  entryname = binary.section_from_rva(entry_point).name
  new_section = lief.PE.Section(entryname + "".join(chr(random.randrange(ord('.'), ord('z'))) for _ in range(3)))
  # push [old_entry_point]; ret
  new_section.content = [0x68] + list(struct.pack("<I", entry_point + 0x10000)) + [0xc3]
  new_section.virtual_address = max([s.virtual_address + s.size for s in binary.sections])
  binary.add_section(new_section, lief.PE.SECTION_TYPES.TEXT)
  binary.optional_header.addressof_entrypoint = new_section.virtual_address
  ```
  * Ý tưởng: tạo section mới với stub `push <old_EP + 0x10000>; ret`, đổi `AddressOfEntryPoint` trỏ vào stub. Stub push địa chỉ EP gốc lên stack rồi `ret` → equivalent với `jmp old_EP`.
  * **Status:** bị disable trong `ACTION_TABLE` ([manipulate.py:300](../FAME-master/FAME-master/data/manipulate.py#L300)):
    ```python
    #   'create_new_entry': 'create_new_entry', # generates often entry point errors
    ```
  * Lý do fail: code dùng `entry_point + 0x10000` là hack ước lượng ImageBase → không account cho base relocation, khác ImageBase giữa các binary. Comment tác giả trong gym-malware gốc: *"this may have a few technical issues with it (not accounting for relocations), but is a proof of concept"*.
* **Không gian & Khả năng đảo ngược:** **Problem-space theo thiết kế**, nhưng không reliable do bug base-address. Không có action canonical ngoài `NEW_ENTRYPOINT` thực sự chạy được trong FAME/gym-malware.

---

## Bảng ánh xạ tóm tắt — FAME

| Tên gốc (ID) | Canonical | Thao tác | Vị trí | Budget / Content |
|---|---|---|---|---|
| overlay_append (0) | `OVERLAY_APPEND` | Thêm | EOF | 32–256 byte, upper random |
| imports_append (1) | `IMPORTS_APPEND` / `IAT_INJECTION` | Thêm | IAT (LIEF rebuild + trampoline) | 1 entry từ pool DLL thật |
| section_rename (2) | `SECTION_RENAME` | Sửa | Section Name field (7 char) | Tên từ `section_names.txt` |
| section_add (3) | `SECTION_ADD` | Thêm | Section Table | 6 char ASCII name, 32–256 byte random, type random từ 9 loại |
| section_append (4) | `SLACK_SPACE_FILL` / `SECTION_APPEND_BYTES` | Thêm | Slack của section random | 32–256 byte, capped bởi available |
| remove_signature (5) | `REMOVE_SIGNATURE` | Xóa | `DataDir[CERTIFICATE_TABLE]` | Unlink pointer only |
| remove_debug (6) | `REMOVE_DEBUG` | Xóa | `DataDir[DEBUG]` | Unlink pointer only |
| upx_pack (7) | `UPX_PACK` / `PACKING` | Nén | Toàn file | Level 1-9 random + options |
| upx_unpack (8) | `UPX_UNPACK` | Gỡ nén | Toàn file | `upx -d` |
| break_optional_header_checksum (9) | `BREAK_CHECKSUM` | Sửa | `OptionalHeader.CheckSum` | Set 0 |
| *create_new_entry (disabled)* | `NEW_ENTRYPOINT` + `SECTION_ADD` | Thêm + Sửa EP | Section mới + `AddressOfEntryPoint` | Stub `push; ret`. **Disabled** vì bug relocation |

## Ghi chú quan trọng — FAME

1. **FAME = gym-malware wrapper, không đề xuất action mới.** [manipulate.py:1](../FAME-master/FAME-master/data/manipulate.py#L1) ghi rõ "Source: https://github.com/endgameinc/gym-malware". Value của FAME là ở lớp **orchestration + validation** (ARMED random, AIMED GP, AIMED-RL, GAME-UP universal perturbations) + pipeline xác thực functionality qua sandbox thật (Cuckoo/VT/HA/MetaDefender).
2. **Pool content benign thật**: [`small_dll_imports.json`](../FAME-master/FAME-master/data/small_dll_imports.json) chứa DLL/function thật (ADVAPI32.DLL + CryptSetProvParam, ...). Khác DQEAF (random ASCII → không resolve được) và tương đương MAB-malware (từ benign pool). Đây là lý do FAME AE "functionally valid" hơn DQEAF.
3. **upx_unpack là unique** trong nhóm paper đã phân tích: 2 action inverse (pack + unpack) → agent có thể "re-pack" hoặc "un-pack then re-pack with different options". Với dataset MAB-malware (Zbot/Locker/Mediyes/Winwebsec/Zeroaccess) có nhiều sample đã UPX-packed sẵn, `upx_unpack` là action khởi đầu quan trọng.
4. **create_new_entry bị disable**: FAME thừa nhận action `NEW_ENTRYPOINT` không reliable trong thực tế. Comment "`generates often entry point errors`" → đây là data point rằng action "Create New Entry" là bất khả thi với approach đơn giản kiểu `push+ret` stub (cần xử lý relocation đúng). Nếu canonical list có `NEW_ENTRYPOINT`, cần ghi nhận rằng không có framework problem-space nào trong 4 paper đã phân tích triển khai reliable — chỉ có OBFU-mal's Darkarmour XOR action là redirect EP qua dropper stub.
5. **Section append mismatch lại tái xuất**: 3/4 framework (OBFU-mal, MAB-malware, FAME) đều có action tên "section_append" mà thực chất là fill slack. Mẫu này có vẻ phổ biến vì đơn giản hơn việc resize raw section.
6. **section_add trong FAME dùng tên không có `.` prefix** (6 char trong `. .. z`), khác DQEAF (`.` + 4-7 char). Có thể là bug của gym-malware gốc — khiến detector dễ flag tên section bất thường.
7. Canonical action **không có** trong FAME: `HEADER_PERTURB`, `SLACK_SPACE_FILL` (có nhưng đặt tên là section_append), `DOS_HEADER_*`, `CONTENT_SHIFT`, `XOR_ENCRYPTION`, `DROPPER`, `TIMESTAMP`, `CODE_REWRITE_*`, `CODE_TRANSLATION`, `CODE_RANDOMIZE`, `CFG_*`, `SEMANTIC_NOP_INJECT`, `BYTECODE_API_HIJACKING`. FAME **không có action code-level** nào — là nhược điểm so với MAB-malware (có CR).
