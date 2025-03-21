-- 插入测试用户
INSERT INTO users (username, password, email) VALUES
('admin', 'admin123', 'admin@example.com'),
('user1', 'password1', 'user1@example.com'),
('user2', 'password2', 'user2@example.com'),
('testuser', 'test123', 'test@example.com');

-- 插入产品数据
INSERT INTO products (name, description, price, category, stock) VALUES
('手机', '高性能智能手机', 2999.99, '电子产品', 100),
('笔记本电脑', '轻薄商务笔记本', 5999.99, '电子产品', 50),
('键盘', '机械游戏键盘', 299.99, '配件', 200),
('鼠标', '无线游戏鼠标', 199.99, '配件', 150),
('耳机', '高清音质耳机', 499.99, '音频设备', 80),
('平板电脑', '10英寸平板电脑', 1999.99, '电子产品', 60),
('显示器', '27英寸4K显示器', 1499.99, '电子产品', 40),
('打印机', '彩色激光打印机', 899.99, '办公设备', 30),
('路由器', '双频WiFi路由器', 249.99, '网络设备', 70),
('摄像头', '高清网络摄像头', 349.99, '配件', 45);

-- 插入订单数据
INSERT INTO orders (user_id, total_amount, status, shipping_address) VALUES
(1, 5999.99, '已完成', '北京市海淀区科学院南路'),
(2, 3499.97, '已发货', '上海市浦东新区张江高科技园区'),
(3, 2199.98, '待发货', '广州市天河区体育西路'),
(4, 7499.98, '已完成', '深圳市南山区科技园');

-- 插入订单项数据
INSERT INTO order_items (order_id, product_id, quantity, price) VALUES
(1, 2, 1, 5999.99),
(2, 1, 1, 2999.99),
(2, 3, 1, 299.99),
(2, 4, 1, 199.99),
(3, 5, 2, 499.99),
(3, 9, 1, 249.99),
(3, 10, 1, 349.99),
(4, 2, 1, 5999.99),
(4, 7, 1, 1499.99);

-- 插入文件记录
INSERT INTO files (filename, filepath, content_type, size) VALUES
('test.txt', '/uploads/test.txt', 'text/plain', 1024),
('image.jpg', '/uploads/image.jpg', 'image/jpeg', 1048576),
('document.pdf', '/uploads/document.pdf', 'application/pdf', 2097152);

-- 插入命令执行记录
INSERT INTO command_executions (command, executed_by, status, output) VALUES
('ls -la', 'admin', '成功', 'total 32\ndrwxr-xr-x 2 root root 4096 Jan 1 12:00 .\ndrwxr-xr-x 6 root root 4096 Jan 1 12:00 ..\n-rw-r--r-- 1 root root 8192 Jan 1 12:00 file1.txt\n-rw-r--r-- 1 root root 4096 Jan 1 12:00 file2.txt'),
('cat /etc/passwd', 'admin', '失败', '权限被拒绝'),
('ping -c 4 example.com', 'user1', '成功', 'PING example.com (93.184.216.34): 56 data bytes\n64 bytes from 93.184.216.34: seq=0 ttl=56 time=11.632 ms\n64 bytes from 93.184.216.34: seq=1 ttl=56 time=11.726 ms\n64 bytes from 93.184.216.34: seq=2 ttl=56 time=10.683 ms\n64 bytes from 93.184.216.34: seq=3 ttl=56 time=11.127 ms');

-- 插入查询记录
INSERT INTO query_logs (query_text, executed_by, status, affected_rows) VALUES
('SELECT * FROM users', 'admin', '成功', 4),
('UPDATE products SET stock = stock - 1 WHERE id = 1', 'admin', '成功', 1),
('SELECT * FROM products WHERE category = ''电子产品''', 'user1', '成功', 4),
('DELETE FROM orders WHERE status = ''已取消''', 'admin', '成功', 0); 