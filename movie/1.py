import os

# 获取当前目录
current_directory = os.getcwd()

# 遍历当前目录下的所有文件
for filename in os.listdir(current_directory):
    # 检查文件是否以 "(2).webp" 结尾
    if filename.endswith(".webp"):
        new_filename = filename.replace(" ", "")
        # 重命名文件
        os.rename(os.path.join(current_directory, filename), os.path.join(current_directory, new_filename))
        print(f'Renamed: {filename} -> {new_filename}')