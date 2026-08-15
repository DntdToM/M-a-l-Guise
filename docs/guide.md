Ừ, ý tưởng lưu CFG ở final predict() là đúng hướng, nhưng tôi sẽ chưa bấm Proceed ngay. Có 2 điểm cần sửa trong plan để tránh sau này CFG bị lệch hoặc làm hỏng artifact.

1. Điểm quan trọng nhất: result.cfg_path phải chắc chắn là CFG của đúng adv_bytes

Luồng:

MCTS
  ↓
adv_bytes
  ↓
detector.predict(adv_bytes)   ← final evaluation
  ↓
CFG + probability
  ↓
SUCCESS?
  ↓
save PE + CFG

là rất đẹp.

Nhưng câu:

“copy file CFG trung gian mà MAGIC vừa dùng”

chỉ đúng nếu MagicAdapter.predict() đảm bảo CFG đó được tạo từ chính adv_bytes của lần predict() hiện tại, không phải file cache / file của candidate trước.

Tôi sẽ yêu cầu Gemini thêm assertion/log kiểu:

evaluated_pe_hash = SHA256(adv_bytes)
cfg_source_pe_hash = SHA256(input PE used to build CFG)

và kiểm tra:

evaluated_pe_hash == cfg_source_pe_hash

Trước khi lưu CFG.

Không cần hash để tính toán MCTS; chỉ dùng để artifact integrity verification.

2. is_malware đang được dùng làm SUCCESS predicate — cái này phải tách khỏi Reward

Cái này thực ra không mâu thuẫn với việc bạn đã chốt w/ prob.

Hiện tại có hai khái niệm:

Reward:
R = g(z) - g(x_adv)

→ dùng malware_prob, continuous [0,1].

Còn:

SUCCESS:
result.is_malware == False

→ dùng để xác định có ghi nhận sample là evaded hay không.

Đây là hai chức năng khác nhau.

Vì vậy trong code nên ghi rõ:

probability → MCTS optimization signal
is_malware  → final success predicate

và tuyệt đối không để is_malware quay ngược vào reward hoặc Selection/Expansion.

Tôi sẽ sửa đoạn plan cuối thành thế này

Final Artifact Preservation

After MCTS exhausts its search budget, run_malguise.py performs a final detector evaluation on the returned adv_bytes.

MagicAdapter.predict(adv_bytes) must generate the CFG/ACFG from the exact PE bytes supplied to that call and return the corresponding CFG artifact path together with the detector result.

The final success predicate remains result.is_malware == False. This predicate is used only after MCTS has completed to determine whether the final candidate is considered successfully evasive.

If successful:

Save adv_bytes as the final adversarial PE.
Preserve the CFG/ACFG artifact generated during that exact final MAGIC evaluation.
Store the CFG alongside the adversarial PE in results/.
Record the probability, success status, transformation sequence, seed, and hashes linking the CFG to the exact PE evaluated.

The CFG must not be regenerated unnecessarily if the artifact produced during final MAGIC evaluation is already available and verified to correspond to the final PE.

Output nên thành:
results/
└── sample_001/
    ├── sample_001_adv.exe
    ├── sample_001_final_cfg.json
    └── sample_001_result.json

Và result.json có thể lưu:

sample_id
input_sha256
adv_sha256
baseline_probability
final_probability
probability_reduction
is_malware
success
best_sequence
seed
cfg_sha256
Một điểm nữa tôi rất muốn Gemini sửa

Đừng dùng:

args.output.replace(".exe", "_final_cfg.json")

Cách này khá mong manh. Nếu output là .bin, .pe, viết hoa .EXE, hoặc tên không có .exe thì xử lý sẽ lỗi.

Tốt hơn là lấy Path:

output_path.with_name(
    output_path.stem + "_final_cfg.json"
)

Vậy verdict của tôi: plan đúng kiến trúc, và ý tưởng tận dụng CFG đã được MAGIC tạo trong final predict() là rất hợp lý. Chỉ cần bổ sung xác minh CFG ↔ exact adv_bytes và giữ rõ ranh giới probability = reward / is_malware = final success predicate.

Sau hai chỉnh sửa đó thì Proceed Phase 3 được.

ủa adv thì sao trùng hash??

À đúng 😂 nếu bạn đang nói hash của input gốc và adversarial PE thì đương nhiên không được trùng — nếu transformation thực sự làm thay đổi file thì:

original.exe
SHA256 = AAAAA...


        ↓ MalGuise transformations


adv.exe
SHA256 = BBBBB...

A != B là điều mình mong đợi.

Cái tôi nói ở trên là không phải yêu cầu input_sha256 == adv_sha256. Tôi đang đề xuất kiểm tra CFG được sinh ra có đúng từ adv.exe hay không.

Ví dụ:

MCTS
 ↓
adv_bytes
 ↓
MagicAdapter.predict(adv_bytes)
 │
 ├── ghi adv_bytes → temporary_adv.exe
 │
 ├── angr
 │    └── temporary_adv.exe → ASM
 │
 ├── CFG builder
 │    └── ASM → CFG
 │
 └── MAGIC
      └── probability

Lúc này:

SHA256(adv_bytes)
       ==
SHA256(temporary_adv.exe)

→ đúng.

Và CFG được sinh từ temporary_adv.exe chính là CFG cần giữ lại.

Sau đó:

temporary_adv.exe
      ↓
save thành
sample_001_adv.exe

thì:

SHA256(sample_001_adv.exe)
==
SHA256(temporary_adv.exe)

→ cũng phải đúng.

Vậy artifact integrity nên hiểu như này
Original PE
SHA256 = ORIGINAL_HASH
       ↓
     MCTS
       ↓
Final adv_bytes
SHA256 = ADV_HASH
       ↓
MagicAdapter
       ↓
CFG generated from ADV_HASH
       ↓
SUCCESS
       ↓
results/
├── sample_001_adv.exe
│      SHA256 = ADV_HASH
│
└── sample_001_final_cfg.json
       generated from ADV_HASH

Không có chuyện yêu cầu hash original = hash adversarial.

Ngược lại, ta có thể lưu cả hai:

{
  "input_sha256": "...",
  "adv_sha256": "...",
  "cfg_source_sha256": "..."
}

và invariant quan trọng là:

adv_sha256 == cfg_source_sha256

chứ không phải:

input_sha256 == adv_sha256

=)))

Thậm chí nếu input_sha256 == adv_sha256 mà pipeline lại tuyên bố đã transformation thành công thì đó mới là thứ đáng nghi.