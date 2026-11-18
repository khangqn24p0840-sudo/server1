# ScamShield VN Server

Máy chủ cho mục **☁️ Tài khoản & đồng bộ** của app ScamShield: đăng ký/đăng nhập, phân tích AI,
danh sách số lừa đảo cộng đồng, thống kê ẩn danh (chỉ khi người dùng đồng ý) và khảo sát.

## 1. Chạy thử trên máy (không cần Docker)

    pip install -r requirements.txt
    export ADMIN_KEY=chuoi-bi-mat-cua-ban
    python server.py            # chạy ở http://localhost:8000
    curl http://localhost:8000/health

## 2. App yêu cầu HTTPS, chọn một cách

**A. Không có tên miền, để thử nhanh** (Cloudflare Tunnel, miễn phí):

    cloudflared tunnel --url http://localhost:8000

Lệnh sẽ in ra một địa chỉ dạng `https://xxxx.trycloudflare.com`. Dán địa chỉ đó vào ô
"Địa chỉ máy chủ" trong app. (Địa chỉ đổi mỗi lần chạy lại, chỉ dùng để thử.)

**B. Chạy lâu dài trên VPS** (có tên miền trỏ về VPS):

    cp .env.example .env        # cấu hình GEMINI_API_KEY và ADMIN_KEY
    # sửa tên miền trong Caddyfile
    docker compose up -d --build

Caddy tự cấp chứng chỉ HTTPS. Địa chỉ cần nhập vào app: `https://ten-mien-cua-ban`.

## 3. ML TFLite: phát hành model để app tự cập nhật

Server Flask chính cũng cung cấp model ML, không cần chạy `ml/model_server.py` riêng.

Các endpoint công khai:
- `GET /api/model/manifest` — version, SHA-256, kích thước.
- `GET /api/model/scam_text.tflite` — file TFLite.

Đặt model ngoài APK vào `data/models/` (hoặc thư mục từ `MODEL_DIR`).

Sau khi huấn luyện trên máy tính:

    python publish_model.py --model ../ml/exports/scam_text.tflite --version 2

Lần sau tăng version lên 3, 4, 5... App sẽ kiểm tra version khi mở/quay lại ứng dụng và tải model mới nếu version cao hơn. App tự kiểm tra model trước khi kích hoạt; nếu cập nhật thất bại, model đang dùng vẫn được giữ.

Có thể upload trực tiếp qua API quản trị:

    curl -X POST https://DIACHI/admin/model/publish \
      -H "X-Admin-Key: KHOA" \
      -F "version=2" \
      -F "model=@../ml/exports/scam_text.tflite"

Chỉ dùng HTTPS khi kết nối từ điện thoại. Nếu chỉ chạy `python server.py` trên máy tính để thử, dùng Cloudflare Tunnel hoặc hạ tầng HTTPS tương đương.

## 4. Cấu hình Gemini và Theo dõi chat

Máy chủ dùng Google Gemini cho các tính năng AI văn bản. Khi model chính gặp timeout hoặc HTTP 500/502/503/504, server tự thử lại một lần sau 1 giây rồi thử model dự phòng GEMINI_FALLBACK_MODEL (mặc định gemini-3.5-flash-lite) thêm một lần. Lỗi khóa/quyền/model/hạn mức như 401/403/404/429 không bị lặp vô ích. Mỗi lượt gọi có timeout 20 giây. Cấu hình hai biến sau trong môi trường chạy server hoặc file `.env` riêng trên máy chủ; không đưa khóa thật lên GitHub:

```env
GEMINI_API_KEY=KHOA_GOOGLE_AI_STUDIO_CUA_BAN
GEMINI_MODEL=gemini-3.8-flash
GEMINI_FALLBACK_MODEL=gemini-3.5-flash-lite
```

Nếu không có `GEMINI_API_KEY`, các bộ quy tắc cục bộ vẫn hoạt động, nhưng các yêu cầu phân tích Gemini trả về lỗi cấu hình rõ ràng.

### API phân tích ngữ cảnh hội thoại

`POST /api/monitor/conversation` yêu cầu đăng nhập và nhận tối đa 12 tin nhắn thuộc **một cuộc trò chuyện đã chọn**:

```json
{
  "messages": [
    {"sender": "Người gửi", "text": "Nội dung tin nhắn", "timestamp": 1794900000000}
  ]
}
```

Máy chủ gửi nội dung này trực tiếp tới Gemini để trả về `risk_score`, `risk_level`, `summary`, `evidence`, `recommended_action`, `confidence` và `conversation_memory`. App có thể gửi kèm trường `memory` là bản tóm tắt ngữ cảnh có cấu trúc của chính thread đó. Bộ nhớ được lưu cục bộ trên thiết bị và gửi lại ở lần phân tích sau; server chỉ xử lý trong yêu cầu hiện tại, không lưu transcript hoặc bộ nhớ vào cơ sở dữ liệu/log. Bộ nhớ gồm tóm tắt, sự kiện, hành vi quan sát được và điểm còn cần xác minh; server giới hạn kích thước và số mục. Endpoint giới hạn 12 yêu cầu/phút/tài khoản, giới hạn transcript 6.000 ký tự. App chỉ gọi endpoint sau khi người dùng đồng ý bật phân tích tự động trong Theo dõi chat, hoặc chủ động bấm phân tích. Xóa đối tượng theo dõi cũng xóa bộ nhớ liên quan trên thiết bị.

Endpoint `/api/chat` và giao diện chatbot thông thường vẫn giữ giao thức cũ, độc lập với endpoint theo dõi chat.

Lưu ý: Android chỉ cung cấp cho app nội dung mà ứng dụng nhắn tin hiển thị trong thông báo. Không thể đảm bảo thu được toàn bộ lịch sử hoặc cả hai chiều tin nhắn. Kết quả Gemini là chỉ báo rủi ro, không phải kết luận chắc chắn.

## 3b. Tra cứu tài khoản ngân hàng (VietQR)

Danh sách ngân hàng được tải từ API công khai VietQR. Tra tên chủ tài khoản yêu cầu
credentials do quản trị viên cấu hình trên server (không nhúng vào APK):

    VIETQR_CLIENT_ID=...
    VIETQR_API_KEY=...

Đặt hai biến này trong môi trường chạy server hoặc file .env do launcher nạp, sau đó khởi động lại.
App gọi POST /api/bank/lookup qua máy chủ đã đăng nhập; server không lưu số tài khoản hay tên trả về.
Tên chủ tài khoản chỉ giúp đối chiếu người nhận, không chứng minh tài khoản an toàn hoặc không liên quan lừa đảo.
VietQR có thể giới hạn hỗ trợ theo ngân hàng và gói dịch vụ.

## 4a. Trang quản trị và giám sát AI

Lịch sử chi tiết dashboard AI lưu tối đa 500 sự kiện trong 30 ngày. Mỗi bản ghi chỉ có loại tính năng,
trạng thái, thời gian, thời lượng, bản xem trước yêu cầu đã che số điện thoại, email, dãy số dài,
trường OTP/mật khẩu và tham số truy vấn URL, cùng lý do lỗi Gemini. Với Theo dõi chat, chỉ lưu số lượng/
kích thước tin nhắn; không lưu transcript. Ảnh không được lưu. Quản trị viên có thể xóa lịch sử trong dashboard.


Mở `/admin` từ chính máy chạy server và đăng nhập bằng `ADMIN_KEY`.
Mục **AI & Hệ thống** hiển thị cấu hình Gemini, model, thời điểm gọi gần nhất,
lượt thành công/thất bại riêng cho **Theo dõi chat** và **Chatbot thông thường**,
thời điểm server khởi động và tình trạng file TFLite. Thời gian hiển thị theo múi giờ Việt Nam.
Số liệu lời gọi AI chỉ được giữ trong bộ nhớ của tiến trình server và đặt lại khi khởi động lại;
không lưu transcript, nội dung hội thoại hay API key vào bảng giám sát.

## 4. Quản lý danh sách số lừa đảo cộng đồng

Dùng header `X-Admin-Key` (giá trị `ADMIN_KEY`). Số được tự chuẩn hóa về dạng `+84...`.

    # thêm số
    curl -X POST https://DIACHI/admin/blocklist -H "X-Admin-Key: KHOA" \
         -H "Content-Type: application/json" \
         -d '{"numbers":["0901234567","+84 28 3822 1234"],"source":"tu-bao-cao"}'

    # xóa một số
    curl -X DELETE https://DIACHI/admin/blocklist/0901234567 -H "X-Admin-Key: KHOA"

    # thống kê (số tài khoản, số trong danh sách, thống kê cảnh báo ẩn danh)
    curl https://DIACHI/admin/stats -H "X-Admin-Key: KHOA"

Trong app: đăng nhập rồi bấm nút tải danh sách, app sẽ báo "Đã thêm N số lừa đảo từ cộng đồng".


## 4c. Cộng đồng: bảng cảnh báo trực tiếp + bình luận công khai

- **Xem không cần đăng nhập** (bảng "Cảnh Báo Nổi Bật" trên Trang chủ và tab Cộng đồng). **Đăng bài, thích, bình luận, báo cáo cần đăng nhập.**
- App hỏi server "có gì mới không" mỗi 8 giây (bảng tin) và 5 giây (trang chi tiết), chỉ khi màn hình đang mở.
  Nếu không có thay đổi, server trả về rất gọn (tham số `rev`), nên nhẹ cho cả máy bạn lẫn gói ngrok miễn phí.
- Mỗi cảnh báo có: chủ đề (Ngân hàng, Mạng xã hội, Điện thoại, Việc làm, Khác), mức độ (Thấp, Trung bình, Cao), tiêu đề, nội dung (5–1000 ký tự).
- **Tên tác giả do server quyết định** (lấy từ "Tên hiển thị" của tài khoản), app không tự khai được. Tên 2–24 ký tự và
  bị chặn nếu giả danh: admin, quản trị, ScamShield, công an, hỗ trợ, chính thức…
- Giới hạn: 5 bài/phút và 20 bài/ngày, 8 bình luận/phút và 100 bình luận/ngày cho mỗi tài khoản.
- Bài hoặc bình luận bị **3 người khác nhau báo cáo** sẽ tự ẩn (đổi bằng biến `REPORT_HIDE`).
- Trang `/admin` có thêm tab **Bình luận** và form **Đăng cảnh báo chính thức** (nhãn "CHÍNH THỨC", tác giả ScamShield).
  Nên đăng vài cảnh báo thật đã kiểm chứng để bảng tin không trống lúc đầu.
- Nội dung công khai: hãy xem tab Bài đăng và Bình luận thường xuyên, vì bài có thể chứa số điện thoại hay tên người.
- Bản cập nhật tự nâng cấp CSDL cũ (thêm cột, thêm bảng), không mất dữ liệu.


## 4d. Dashboard (tab "Tổng quan" trong /admin)

Mở `http://127.0.0.1:8000/admin`, tab **Tổng quan** hiện đầu tiên. Gồm: số tài khoản, bài đăng, bình luận, số bị chặn (kèm số mới hôm nay),
biểu đồ 7/14/30 ngày (tài khoản mới, bài đăng, bình luận, cảnh báo ẩn danh), cảnh báo theo chủ đề, cảnh báo từ máy người dùng theo loại,
hàng chờ cần xử lý (bài và bình luận bị ẩn hoặc bị báo cáo, bấm "Xem" để nhảy sang tab tương ứng), người đóng góp nhiều nhất và đăng ký gần đây.
Tự làm mới mỗi 30 giây khi tab đang mở. Giờ theo múi giờ của máy chạy server. Dữ liệu chỉ có trong trang quản trị (mở được từ chính máy server).

Muốn phân tích sâu hơn (biểu đồ tự thiết kế, truy vấn tùy ý): dùng Metabase hoặc Grafana nối thẳng vào file `data/scamshield.db`.
Chỉ nên cấp quyền ĐỌC, vì file chứa email người dùng.


## 4e. Tin báo chí (đọc RSS của các báo)

Server tự tải RSS của các báo định kỳ (mặc định 30 phút, biến `NEWS_INTERVAL_MIN`), chỉ giữ bài có từ khóa liên quan lừa đảo
(lừa đảo, giả mạo, mạo danh, chiếm đoạt, OTP, phishing, deepfake, mã độc…), phân loại chủ đề, bỏ trùng, và chỉ lưu
**tiêu đề, tóm tắt tối đa 240 ký tự, tên báo, ngày đăng và liên kết**. App hiện thành thẻ "📰 TIN BÁO" trong bảng Cảnh Báo Nổi Bật
(có ô lọc "📰 Báo chí"); bấm vào thì mở **bài gốc** trên trình duyệt. Không lưu toàn văn, không lưu ảnh.

- Nguồn mặc định: VnExpress (Pháp luật, Số hóa), Tuổi Trẻ (Tin mới), Thanh Niên (Trang chủ). Địa chỉ lấy từ danh bạ RSS công khai.
  Tab **Tin báo chí** trong `/admin` cho phép thêm, tắt, xóa nguồn, xem kết quả lần tải gần nhất (nguồn lỗi sẽ hiện chữ "Lỗi: ..."),
  bấm "Tải tin ngay" để chạy ngay, ẩn hoặc xóa từng bài không phù hợp.
- **Điều khoản:** mỗi báo có điều khoản dùng RSS riêng (ví dụ có báo chỉ cho phép cá nhân/tổ chức phi lợi nhuận và yêu cầu ghi rõ nguồn).
  Bạn tự chịu trách nhiệm đọc điều khoản và tắt nguồn nếu báo không cho phép. Nếu app có thu phí hoặc quảng cáo, hãy xin phép báo trước.
- An toàn: chỉ nhận địa chỉ http/https, từ chối địa chỉ nội bộ (localhost, 192.168.x.x…) kể cả khi bị chuyển hướng, giới hạn 2 MB mỗi nguồn,
  chặn XML độc hại, giữ tối đa 60 ngày (`NEWS_KEEP_DAYS`).
- Tắt hẳn tính năng tự tải: đặt `NEWS_ENABLED=false`. Máy chạy server cần có Internet.
- Bộ lọc từ khóa chỉ là chỉ báo: đôi khi lọt bài không liên quan (ví dụ "giả mạo giấy tờ"), hãy ẩn bài đó trong tab Tin báo chí.

## 4f. Chat gia đình (nhóm riêng, đồng bộ nhiều điện thoại)

Chat gia đình dùng tài khoản ScamShield hiện có. Mỗi thành viên đăng nhập bằng tài khoản riêng; người tạo nhóm là trưởng nhóm. Thành viên trong nhóm có thể tạo mã mời để người thân nhập vào tham gia.

Các API đều yêu cầu \`Authorization: Bearer <token>\`:
- \`GET /api/family/chats\`: danh sách nhóm, số thành viên, tin nhắn cuối và số tin chưa đọc.
- \`POST /api/family/chats\`: tạo nhóm, body \`{"name":"Gia đình mình"}\`.
- \`POST /api/family/chats/join\`: tham gia bằng body \`{"invite_code":"..."}\`.
- \`POST /api/family/chats/{id}/invite\`: tạo mã mời ngẫu nhiên, hết hạn sau 7 ngày, tối đa 20 lượt. Database chỉ lưu SHA-256 của mã.
- \`GET /api/family/chats/{id}/members\`: danh sách thành viên.
- \`GET /api/family/chats/{id}/messages?limit=50\`: tải lịch sử tin nhắn và cập nhật mốc đã đọc.
- \`POST /api/family/chats/{id}/messages\`: gửi body \`{"body":"..." }\`, tối đa 2.000 ký tự.
- \`POST /api/family/chats/{id}/leave\`: rời nhóm; nếu trưởng nhóm rời, quyền trưởng nhóm chuyển cho thành viên vào sớm nhất.
- \`DELETE /api/family/chats/{id}\`: chỉ trưởng nhóm được xóa nhóm và toàn bộ lịch sử.

**Quyền riêng tư và giới hạn:** máy chủ kiểm tra membership ở từng lần đọc/gửi; người ngoài nhóm nhận 404. Giới hạn 30 tin/phút và 1.000 tin/ngày cho mỗi tài khoản. App Android hiện đồng bộ bằng cách hỏi máy chủ định kỳ khoảng 6 giây khi phòng chat đang mở.

Tin nhắn được lưu trong SQLite để đồng bộ giữa các thiết bị. Nội dung truyền qua HTTPS nhưng **chưa có mã hóa đầu cuối (E2EE)**; người vận hành máy chủ có thể truy cập dữ liệu lưu trữ. Không gửi OTP, mật khẩu, thông tin thẻ hoặc dữ liệu riêng tư nhạy cảm vào nhóm. Sao lưu thư mục \`data/\` theo chính sách bảo mật của bạn.

## 5. Dùng trong app

1. Mở mục "Tài khoản & đồng bộ", nhập địa chỉ máy chủ `https://...`
2. Nhập email + mật khẩu (từ 8 ký tự) → **Đăng ký** (lần đầu) hoặc **Đăng nhập**.
3. Khi chỉ dùng cho mình, đặt `ALLOW_REGISTRATION=false` sau khi đã tạo tài khoản.

## Bảo mật và quyền riêng tư

- Mật khẩu được băm (không lưu bản gốc); đăng nhập bằng token 30 ngày.
- Server **không ghi lại nội dung** tin nhắn/ảnh đã phân tích.
- Thống kê chỉ lưu khi bật đồng ý; tắt đồng ý hoặc "Xóa tài khoản" sẽ xóa dữ liệu liên quan.
- Có giới hạn tần suất cơ bản theo IP/tài khoản. Hãy đặt `ADMIN_KEY` dài, khó đoán.
- Dữ liệu nằm trong thư mục `data/` (SQLite), nhớ sao lưu.

## 6. Trang quản lý tài khoản (trình duyệt)

Chạy server rồi mở **http://localhost:8000/admin** trên chính máy chạy server, nhập `ADMIN_KEY`.
Xem/tìm tài khoản, khóa/mở khóa (khóa xong người dùng bị đăng xuất ngay), đặt lại mật khẩu
(để trống = tự sinh mật khẩu tạm), xóa tài khoản, quản lý danh sách số lừa đảo và xem khảo sát.

Mặc định `ADMIN_LOCAL_ONLY=true`: trang và API quản trị **không mở được qua ngrok/tunnel/internet**, chỉ
mở từ localhost. Trên VPS (qua Caddy), hãy dùng SSH tunnel (`ssh -L 8000:localhost:8000 user@vps`, rồi mở
localhost:8000/admin, cần publish cổng 8000 của api) hoặc đặt `ADMIN_LOCAL_ONLY=false` kèm `ADMIN_KEY` thật dài.

## 7. Cộng đồng (bài đăng)

Trong app có tab **Cộng đồng**: người dùng đã đăng nhập xem, đăng bài (5–1000 ký tự, 3 mục: Cảnh báo / Hỏi đáp /
Kinh nghiệm), thích, báo cáo và xóa bài của mình. Giới hạn: 5 bài/phút, 20 bài/ngày mỗi tài khoản.
Bài có từ `REPORT_HIDE` (mặc định 3) người báo cáo sẽ tự ẩn. Vào **/admin → tab Bài đăng** để Ẩn/Hiện lại hoặc Xóa.
Xóa tài khoản thì bài của tài khoản đó cũng bị xóa. Bài đăng hiển thị công khai cho mọi người dùng.