# MalGuise How To Run

Huong dan nay danh cho may chay phan `data/Test_part_2` da duoc dong goi kem source code.

## 1. Giai nen

Neu nhan file `.7z`:

```bash
7z x MalGuise_with_Test_part_2.7z
cd MalGuise
```

Neu nhan file `.zip`:

```bash
unzip MalGuise_with_Test_part_2.zip
cd MalGuise
```

Sau khi giai nen, thu muc chinh phai co dang:

```text
MalGuise/
  actions/
  cfg/
  core/
  data/
    Test_part_2/
      Locker/
      Mediyes/
      Zbot/
      Zeroaccess/
  detector/
  pipeline/
  scripts/
  search/
  requirements.txt
  requirements_det.txt
  setup.sh
```

## 2. Kiem tra dataset

Chay lenh nay tu trong thu muc `MalGuise/`:

```bash
find data/Test_part_2 -mindepth 2 -maxdepth 2 -type f | sed 's#^data/Test_part_2/##; s#/.*##' | sort | uniq -c
```

Ket qua dung phai la:

```text
49 Locker
290 Mediyes
420 Zbot
138 Zeroaccess
```

Tong so file:

```bash
find data/Test_part_2 -mindepth 2 -maxdepth 2 -type f -name "*.exe" | wc -l
```

Ket qua dung:

```text
897
```

## 3. Cai dat moi truong

Yeu cau nen dung Linux/Ubuntu, Python 3.10, va con du dung luong dia. Qua trinh cai dat se tao virtualenv rieng cho detector tai `detector/det_venv`.

Chay:

```bash
chmod +x setup.sh
./setup.sh
```

Neu thieu goi he thong cho Python virtualenv, cai them:

```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential p7zip-full unzip
```

Sau do chay lai:

```bash
./setup.sh
```

## 4. Kiem tra blackbox detector MAGIC

Detector mac dinh khi batch chay la `magic`. Workflow detector trong code la:

```text
PE bytes
  -> detector/MAGIC adapter ghi ra temp sample.exe
  -> detector/MSACFG/prepare_data.py tao ASM bang angr
  -> detector/MAGIC/maldefender/acfg_pipeline.py tao ACFG
  -> detector/MAGIC/maldefender/predict_model.py load checkpoint .pt
  -> submission.csv
  -> MalwareProb + is_malware tra ve cho MCTS
```

Chay smoke test mot file truoc khi batch lon:

```bash
MPLCONFIGDIR=/tmp/matplotlib python3 -c "from pathlib import Path; import sys; sys.path.insert(0, '.'); from detector.magic_adapter import MagicAdapter; sample=next(Path('data/Test_part_2/Zbot').glob('*.exe')); d=MagicAdapter('detector/MAGIC'); r=d.predict(sample.read_bytes()); print(sample); print('MalwareProb=', r.malware_prob, 'is_malware=', r.is_malware)"
```

Neu workflow dung, lenh se in ra ten sample, `MalwareProb`, va `is_malware`. Co the co warning tu angr hoac torch, mien la lenh ket thuc thanh cong va co probability.

## 5. Chay batch evaluation

Chon so worker theo CPU va dung luong trong `/tmp`. MAGIC rat nang vi moi candidate phai qua `angr -> ACFG -> predict_model.py`.

```text
workers khuyen nghi = 16 den 24
```

Neu may co nhieu CPU nhung `/tmp` con it dung luong, uu tien `--workers 16` hoac `--workers 24`, khong nen day len 36/56.

Lenh chay part 2:

```bash
MPLCONFIGDIR=/tmp/matplotlib python3 scripts/batch_evaluate.py \
  --data-dir data/Test_part_2 \
  --results-dir results \
  --c-budget 40 \
  --max-length 6 \
  --workers 24 \
  --timeout 1800 \
  --resume
```

`--timeout 1800` nghia la moi sample duoc chay toi da 30 phut. Neu qua 30 phut, script se kill ca process tree cua sample do, ghi failure marker, roi chay sample tiep theo.

Batch truyen soft time budget vao MCTS nho hon hard timeout khoang 2 phut. Neu gan het thoi gian ma MCTS da danh gia duoc it nhat mot candidate, pipeline se luu candidate co malicious probability thap nhat da thay. Candidate nay chi duoc tinh la thanh cong neu detector tra `is_malware=False`.

MCTS co early-stop: neu candidate da evade duoc MAGIC (`is_malware=False`) thi sample do dung som, khong doi het full budget `c_budget * max_length`.

## 6. Resume khi bi dung giua chung

Neu may bi mat ket noi, crash, hoac can dung lai, chay lai dung lenh cu:

```bash
MPLCONFIGDIR=/tmp/matplotlib python3 scripts/batch_evaluate.py \
  --data-dir data/Test_part_2 \
  --results-dir results \
  --c-budget 40 \
  --max-length 6 \
  --workers 24 \
  --timeout 1800 \
  --resume
```

Co `--resume` thi script se bo qua sample da co file success:

```text
results/<Family>/<SampleId>/<SampleId>_adv_result.json
```

Va cung bo qua sample da co failure marker:

```text
results/<Family>/<SampleId>/<SampleId>_adv_failure.json
```

Neu muon chay lai cac sample da fail/timeout, them `--retry-failed`:

```bash
MPLCONFIGDIR=/tmp/matplotlib python3 scripts/batch_evaluate.py \
  --data-dir data/Test_part_2 \
  --results-dir results \
  --c-budget 40 \
  --max-length 6 \
  --workers 24 \
  --timeout 1800 \
  --resume \
  --retry-failed
```

Neu muon chay lai cac sample da co best-effort result nhung chua evade (`success=false`), them `--retry-best-effort`.

## 7. Cau truc output dung

Output thanh cong se duoc xep theo dung ho malware goc:

```text
results/
  Locker/
    <sample_id>/
      <sample_id>_adv.exe
      <sample_id>_adv_result.json
      <sample_id>_adv_final_cfg.json
  Mediyes/
    <sample_id>/
      <sample_id>_adv.exe
      <sample_id>_adv_result.json
      <sample_id>_adv_final_cfg.json
  Zbot/
    <sample_id>/
      <sample_id>_adv.exe
      <sample_id>_adv_result.json
      <sample_id>_adv_final_cfg.json
  Zeroaccess/
    <sample_id>/
      <sample_id>_adv.exe
      <sample_id>_adv_result.json
      <sample_id>_adv_final_cfg.json
```

Neu sample fail hoac timeout, output se co:

```text
results/<Family>/<SampleId>/<SampleId>_adv_failure.json
results/_logs/<Family>/<SampleId>.log
```

File `.log` giu stdout/stderr day du cua `pipeline/run_malguise.py`, dung de xem loi that thay vi chi thay `Exit Code 1`.

Neu sample khong evade nhung co candidate tot nhat da duoc luu, metadata se co:

```json
{
  "success": false,
  "status": "best_effort_not_evaded",
  "is_malware": true,
  "final_probability": 0.73
}
```

File `_adv.exe` van ton tai trong truong hop nay; chi khong duoc tinh vao attack success rate.

Vi du input:

```text
data/Test_part_2/Zbot/A.exe
```

Thi output se nam tai:

```text
results/Zbot/A/A_adv.exe
results/Zbot/A/A_adv_result.json
results/Zbot/A/A_adv_final_cfg.json
```

## 8. Theo doi tien trinh

Mo terminal khac trong `MalGuise/` va chay:

```bash
find results -name "*_adv_result.json" | wc -l
find results -name "*_adv.exe" | wc -l
```

Dem theo family:

```bash
find results -mindepth 3 -maxdepth 3 -name "*_adv_result.json" | sed 's#^results/##; s#/.*##' | sort | uniq -c
```

Xem dung luong results:

```bash
du -sh results
```

## 9. Nen results de gui lai

Sau khi batch chay xong, nen thu muc `results/`:

```bash
7z a -t7z MalGuise_results_part_2.7z results \
  -mx=9 -m0=lzma2 -md=1536m -mfb=273 -ms=on -mmt=on
```

Neu may khong co `7z`, dung zip:

```bash
zip -9 -r MalGuise_results_part_2.zip results
```

Gui lai file `MalGuise_results_part_2.7z` hoac `MalGuise_results_part_2.zip`.

## 10. Loi thuong gap

Neu gap loi `No .pt models found`, kiem tra:

```bash
find detector/MAGIC/maldefender/msacfg_models -name "*.pt"
```

Thu muc nay phai co checkpoint `.pt`.

Neu gap loi import Python, chay lai:

```bash
./setup.sh
```

Neu log co warning cua matplotlib ve `/home/.../.config/matplotlib`, chay batch voi:

```bash
MPLCONFIGDIR=/tmp/matplotlib python3 scripts/batch_evaluate.py ...
```

Neu sample nao bi timeout hoac evasion failed, day la ket qua binh thuong cua search budget. Script van tiep tuc chay cac sample con lai.
