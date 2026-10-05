# S-DES 算法实现

这是《信息安全导论》课程作业的 S-DES 实现。

- 10 位密钥扩展，生成 `k1`、`k2`
- 8 位分组加密
- 8 位分组解密
- 暴力破解扩展功能
- 加解密封闭性测试

## 组员

组员 1：刘亚玟  
组员 2：李琳洁  

## 运行环境

- Python 3.9 或更高版本
- 不需要安装第三方库

## 运行示例

在本目录执行：

```powershell
python sdes.py keys --key 1010000010
python sdes.py encrypt --key 1010000010 --plaintext 11010111
python sdes.py decrypt --key 1010000010 --ciphertext 10101000
```

运行结果：

```text
k1=10100100
k2=01000011
10101000
11010111
```

## 测试

运行基础测试：

```powershell
python -m unittest -v
```

运行全部 1024 个密钥和全部 256 个 8 位分组的封闭性测试：

```powershell
python sdes.py exhaustive-test
```

这个测试验证：

```text
decrypt(encrypt(明文, 密钥), 密钥) == 明文
```

## 暴力破解

已知明文和密文时，可以遍历全部 1024 个 10 位密钥：

```powershell
python sdes.py brute-force --plaintext 11010111 --ciphertext 10101000
```

## 算法参数

```text
P10   = 3 5 2 7 4 10 1 9 8 6
P8    = 6 3 7 4 8 5 10 9
IP    = 2 6 3 1 4 8 5 7
IP^-1 = 4 1 3 5 7 2 8 6
EP    = 4 1 2 3 2 3 4 1
P4    = 2 4 3 1
```

`S0`、`S1` 和具体的加解密过程写在 `sdes.py` 中。置换表按照课件中的位置编号使用。

## GitHub 提交流程

1. 在 GitHub 新建一个仓库，例如 `sdes-homework`。
2. 把本目录中的 `sdes.py`、`test_sdes.py`、`README.md` 上传。
3. 先运行测试，确认没有报错。
4. 把仓库链接提交到老师指定的石墨文档。

提交前先运行基础测试，再用一组新的密钥和明文测试一次。
