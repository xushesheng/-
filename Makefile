# 工具链
CC = arm-linux-gnueabihf-gcc

# 源文件
SRC = user_amp.c

# 目标文件
TARGET = user_amp

# 链接库
CFLAGS = -I. -I/usr/arm-linux-gnueabihf/include
LDFLAGS = -lpthread -lpcap

# 默认规则
all: $(TARGET)

# 编译链接规则
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# 清理
clean:
	rm -f $(TARGET)

.PHONY: all clean
