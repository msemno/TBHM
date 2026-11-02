# تشغيل LLM وذاكرة التعلّم على Kali — TBHM 4.2.5

تاريخ المراجعة: 2026-10-22. الأوامر مطابقة لمصدر هذا الإصدار. نفّذ الأقسام بالترتيب، وتوقف عند فشل خطوة بدل لصق كل الأوامر مرة واحدة.

## ما الذي أثبته سجلك؟

| الجزء | الحالة المثبتة من السجل |
|---|---|
| Python 3.12 وبيئة TBHM | تعمل؛ `pip check` لا يعرض متطلبات مكسورة |
| الفحوص الإلزامية | صفر إخفاقات في doctor |
| أدوات الويب الثماني | مسارات nuclei/httpx/subfinder/dnsx/katana/ffuf/nmap/sqlmap موجودة؛ هذا لا يثبت نجاح كل محول أو فحص |
| الإضافات | 20 فحصًا اختياريًا غير ناجح؛ ليست كلها مطلوبة لفحص ويب أو تشغيل LLM |
| الاختبارات في سجلك | 70 من 72 مجموعة نجحت؛ راجع `HOTFIX-regression-environment.md` |
| ذاكرة AI | `not initialized` |
| Ollama والنماذج | `not_checked` بسبب doctor بوضع offline؛ لا يثبت هذا أنها مثبتة أو مفقودة |

تثبيت node/npm/cargo/ruby/composer لا يثبت تنزيل نماذج AI. كذلك `available` في كتالوج القدرات وصف لإمكانية، وليس نتيجة تشغيل.

## اختيار الإعدادات

ابدأ في VM ذات 6 GB RAM بنموذج `qwen2.5:1.5b` وبنموذج embeddings اسمه `nomic-embed-text:v1.5`. الأول نحو 986 MB والثاني نحو 274 MB وقت المراجعة؛ هذه أحجام تنزيل وليست تقدير RAM الكلي. الاختيار بداية محافظة لاختبار التوافق، وليس نتيجة مقارنة تثبت أفضل دقة أمنية.

استخدم طلبًا واحدًا ونموذجًا واحدًا محمّلًا وcontext حجمه 2048 وعامل embeddings واحدًا. أغلق الأعمال الثقيلة أثناء الفهرسة. لا تفترض وصول VMware إلى GPU اللابتوب: تحقق من `ollama ps` عند تشغيل النموذج. لا توجد أوزان نماذج أو مكتبات تدريب داخل ZIP.

```bash
free -h
df -h "$HOME"
command -v ollama
```

## تثبيت Ollama وتشغيله داخل Kali

إذا كان `ollama` موجودًا، تخطّ تنزيل المثبت. خلاف ذلك استخدم المثبت الرسمي:

```bash
mkdir -p "$HOME/tbhm-work"
curl -fL --proto '=https' --tlsv1.2 https://ollama.com/install.sh \
  -o "$HOME/tbhm-work/install-ollama.sh"
sh "$HOME/tbhm-work/install-ollama.sh"
```

بعد نجاح المثبت، اضبط خدمة Ollama داخل Kali. لا تشغّل نسخة ثانية باستخدام `ollama serve` بالتوازي مع الخدمة.

```bash
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo tee /etc/systemd/system/ollama.service.d/tbhm.conf >/dev/null <<'CONF'
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_CONTEXT_LENGTH=2048"
Environment="OLLAMA_KEEP_ALIVE=1m"
Environment="OLLAMA_NO_CLOUD=1"
CONF
sudo systemctl daemon-reload
sudo systemctl enable --now ollama
sudo systemctl restart ollama
systemctl is-active ollama
curl --noproxy '*' --connect-timeout 5 --max-time 15 -fsS \
  http://127.0.0.1:11434/api/tags
```

المتوقع: الخدمة `active` واستجابة JSON. إذا فشلت، اقرأ `journalctl -u ollama -n 60 --no-pager` قبل متابعة تنزيل النماذج. `OLLAMA_NO_CLOUD=1` يعطل ميزات السحابة؛ ليس عزلًا عامًا لشبكة النظام، وتنزيل النماذج ما زال يحتاج إنترنت.

## تنزيل النموذجين واختبار استدعاء حقيقي

```bash
ollama pull qwen2.5:1.5b
ollama pull nomic-embed-text:v1.5
ollama list
ollama --version
```

وجود الاسمين في القائمة لا يكفي؛ جرّب توليدًا فعليًا:

```bash
curl --noproxy '*' --connect-timeout 5 --max-time 300 -fsS \
  http://127.0.0.1:11434/api/chat \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen2.5:1.5b","stream":false,"format":"json","messages":[{"role":"user","content":"Return only this JSON object: {\"ready\":true}"}],"options":{"num_ctx":2048,"num_predict":128,"temperature":0},"keep_alive":0}'
```

المتوقع `done: true` ومحتوى JSON داخل `message.content`. هذا اختبار تشغيل، لا اختبار دقة أمنية. اختبر أيضًا endpoint الـembeddings الذي يستخدمه TBHM:

```bash
curl --noproxy '*' --connect-timeout 5 --max-time 180 -fsS \
  http://127.0.0.1:11434/api/embeddings \
  -H 'Content-Type: application/json' \
  -d '{"model":"nomic-embed-text:v1.5","prompt":"controlled local retrieval readiness test","keep_alive":0}'
```

المتوقع مصفوفة أرقام غير فارغة في `embedding`. إذا فشل الاستدعاء فلا تعتبر RAG جاهزًا لمجرد أن TBHM أنهى أمر التهيئة؛ توجد آلية fallback محددة أدناه.

## ربط TBHM بالذاكرة الدائمة وفهرسة المصدر

من مجلد TBHM الذي ستستخدمه فعليًا:

```bash
cd "$HOME/tools/TBHM-4.2.5"
export TBHM_AI_HOME="$HOME/.local/share/tbhm-ai"
export TBHM_LOCAL_LLM_MODEL="qwen2.5:1.5b"
./tbhm --ai-home "$TBHM_AI_HOME" --ai-init --ai-no-pull \
  --ai-advisor-model qwen2.5:1.5b \
  --local-llm-model qwen2.5:1.5b \
  --ai-embedding-model nomic-embed-text:v1.5 \
  --ai-embedding-workers 1 --local-llm-context 2048
```

`--ai-no-pull` مناسب هنا لأنك نزّلت النموذجين بالفعل. أول فهرسة قد تستغرق وقتًا على CPU؛ لا يوجد زمن ثابت صالح لكل VM. تابع الاستهلاك في terminal أخرى باستخدام `free -h` و`ollama ps` وسجلات الخدمة. لا تبدأ فحصًا ثقيلًا بالتوازي.

البيت الدائم خارج مجلد الإصدار؛ استبدال ZIP لا يمحو الذاكرة. تسجيل أسماء النماذج في `models/model-lock.json` يثبت الاختيار المحلي، ولا يجمد أوزان remote tags عالميًا؛ احتفظ أيضًا بنتيجة `ollama list` للمقارنات. لا تستخدم `--ai-model` لاختيار المستشار: هذا flag آخر لاختبار أهداف AI.

إذا أردت حفظ اختيارات البيئة للجلسات التالية، أضف سطري `export` إلى `~/.zshrc` مرة واحدة. أعِد فتح الطرفية بعد ذلك.

## علامات الجاهزية التي يجب قراءتها

```bash
./tbhm --local-llm-status --local-llm-model qwen2.5:1.5b \
  --local-llm-context 2048
./tbhm --ai-home "$TBHM_AI_HOME" --ai-doctor \
  --ai-embedding-workers 1 --local-llm-context 2048
./tbhm --ai-home "$TBHM_AI_HOME" --ai-regression-check
./tbhm --ai-home "$TBHM_AI_HOME" --ai-verify-audit
```

| الحقل | المطلوب ومعناه |
|---|---|
| `advisor_model_ready` | `true`؛ أضف إليه نجاح استدعاء chat السابق لإثبات inference |
| `vector_index_loaded` | `true`؛ الفهرس يفتح |
| `embedding_mode` | `ollama`؛ القيمة `fallback` تعني hashing حتميًا وليس embeddings النموذج |
| `source_delta_vs_index.stale` | `false`؛ المصدر الحالي مطابق للفهرس |
| `audit_chain.intact` | `true`؛ سلسلة السجل سليمة |

خروج `--ai-init` أو `--ai-doctor` بكود 0 وحده لا يثبت كل هذه الشروط؛ اقرأ الحقول وخطوة `source_indexed`. إذا ظهر fallback، أصلح الخدمة/model/endpoint أولًا ثم أعد `--ai-index-tool --ai-embedding-workers 1`. بعد تغيير ملفات المصدر استخدم `--ai-sync-tool`، وبعد نقل الإصدار استخدم `--ai-migrate` ثم doctor. لا تغيّر نموذج embeddings فوق فهرس سابق دون إعادة فهرسة كاملة.

## تجربة محلية من دون هدف خارجي

هذه عينة مصدر تملكها، لقياس الربط والالتقاط فقط؛ ليست مجموعة تقييم ولا إثبات ثغرة في نظام حقيقي. لا تشغّل `demo.py` نفسه.

```bash
mkdir -p "$HOME/tbhm-work/ai-smoke/src"
cat > "$HOME/tbhm-work/ai-smoke/src/demo.py" <<'PY'
import os
def example(user_input):
    os.system("echo " + user_input)
PY
cat > "$HOME/tbhm-work/ai-smoke/permission.json" <<'JSON'
{
  "schema":"tbhm.run-learning-permission/1",
  "project_id":"owned-lab",
  "scope_reference":"operator-created local ai-smoke source only",
  "source_license":"operator-owned demonstration source",
  "permission_reference":"operator authorizes local processing and reuse of this demonstration only",
  "reuse_approved":true,
  "test_objective":"Check local advisory integration and pending scenario capture; no security ground truth claimed"
}
JSON
./tbhm --profile passive_only \
  --code-dir "$HOME/tbhm-work/ai-smoke/src" \
  --ai-home "$TBHM_AI_HOME" --ai-observe \
  --ai-scenario-context "$HOME/tbhm-work/ai-smoke/permission.json" \
  --local-llm --llm-refute --local-llm-required \
  --local-llm-model qwen2.5:1.5b --local-llm-context 2048 \
  --local-llm-timeout 300 --ai-embedding-workers 1 \
  --local-llm-max-findings 10 --llm-refute-max-findings 5 \
  -o "$HOME/tbhm-work/ai-smoke/run-$(date -u +%Y%m%dT%H%M%SZ)"
```

افتح `OPERATOR.html` و`REPORT_final.html` و`LEARNING.html` من مجلد النتيجة. راجع `execution_ledger.json` وأخطاء triage/refutation؛ `--local-llm-required` يجعل عدم إتاحة النموذج سببًا لعدم اكتمال التشغيل، ولا يضمن جودة كل إجابة. إذا لم تنتج الأداة finding فلن يوجد محتوى للمراجعة.

**لا تضف `--offline` إلى هذا الأمر:** عزل TBHM على Linux يمنع sockets بما فيها localhost، فيمنع Ollama أيضًا. تحليل الملفات بوضع `passive_only` هنا يسمح باستدعاء المستشار المحلي. وللعزل الصارم استخدم `--offline --no-ai-observe` لتحليل الملفات، ثم استدعِ AI في جلسة منفصلة ذات سياسة شبكة تسمح بالمستشار المحلي.

إن كان التشغيل غير مكتمل، حافظ على سجل الخطأ. لا تحذف الأداة الاختيارية أو تغيّر معيار نجاح الفحص لمجرد الحصول على علامة خضراء.

## الذاكرة والتعلّم بعد كل فحص

```bash
./tbhm --ai-home "$TBHM_AI_HOME" \
  --ai-learning examples/learning-v425/02-overview.json
./tbhm --ai-home "$TBHM_AI_HOME" --ai-mistakes
./tbhm --ai-home "$TBHM_AI_HOME" --ai-proposals
./tbhm --ai-home "$TBHM_AI_HOME" --ai-backup
```

الأوامر النموذجية تستخدم `project_id=owned-lab`. غيّره في نسخة من JSON لكل مشروع حقيقي. التقط نتائج المشروع فقط بعد تصريح واضح بالمعالجة وإعادة الاستخدام؛ ملف إذن التجربة أعلاه يخص العينة فقط.

المسار الصحيح: ملاحظة وevidence → حالة `pending` → مراجعة مستقلة تربط الحكم بـcontent hash وIDs الأدلة → استرجاع الحالات المقبولة المسموح بها → نصيحة موثقة → مقارنة baseline/candidate على بيانات مستقلة → موافقة على تحسين محدود. راجع `LEARNING-v4.2.5.md` و`07-review-template.json` لمعاني حقول المراجعة. لا تستبدل placeholders في مثال المراجعة بأحكام `confirmed` بلا دليل مستقل.

ذاكرة السيناريوهات تستخدم SQL/بحثًا نصيًا مقيدًا بالتصريح والمراجعة؛ RAG متجهات المصدر مسار منفصل. حالة الاختبار لا تصبح حقيقة تدريبية لمجرد أن النموذج كررها. يظل `INCONCLUSIVE` صحيحًا عندما ينقص الدليل. النموذج لا يغيّر صلاحيات النطاق ولا يؤكد الثغرة ولا ينفذ اقتراحاته.

تجهيز datasets وفحص صلاحيتها وإلغاء التصاريح متاح. تدريب LoRA/QLoRA وتبديل الأوزان ليسا منفذين في هذا الإصدار، ولا يُطلب تدريب على VM للتشغيل. لا يوجد ادعاء أن نجاح fixtures يقيس دقة نموذج حقيقي؛ يلزم تقييم مستقل بمعايير FP/FN والامتناع وصحة الاستشهادات قبل اعتماد تحسين.

## أعطال شائعة

| العرض | الخطوة التالية |
|---|---|
| `model not found` | طابق الاسم حرفيًا في `ollama list` وflags وmodel lock |
| `Connection refused` | تحقق من خدمة Ollama وcurl `/api/tags` داخل Kali |
| RAM ممتلئة أو بطء شديد | أوقف النماذج عبر `ollama stop MODEL` وأغلق الأعمال الثقيلة، وأبقِ النموذج الواحد/context 2048 |
| embeddings fallback | اختبر `/api/embeddings` ثم أعد الفهرسة كاملة بعد نجاحه |
| فشل محول اختياري | اقرأ أحداث `tool-error` و`partial` في execution ledger؛ عدم اكتمال الفحص ليس نجاحًا |
| source drift | شغّل sync أو migrate من الإصدار الذي تستعمله ثم أعد doctor |

## مصادر التثبيت والنماذج

راجعت المصادر الرسمية في 2026-10-22. لم أنزّل النماذج أو أقس أداءها على VM المستخدم من هذه البيئة.

- [Ollama Linux installation](https://docs.ollama.com/linux)
- [Ollama FAQ: service configuration, concurrency, local operation, memory](https://docs.ollama.com/faq)
- [Qwen2.5 1.5B model and current download size](https://ollama.com/library/qwen2.5:1.5b)
- [Nomic embedding model v1.5 and API examples](https://ollama.com/library/nomic-embed-text:v1.5)
