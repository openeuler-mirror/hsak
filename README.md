# HSAK(Hybrid Storage Acceleration Kit)

## 介绍

随着NVMe SSD、SCM等存储介质性能不断提升，介质层在IO栈中的时延开销不断缩减，软件栈的开销成为瓶颈，急需重构内核IO数据面，减少软件栈的开销，HSAK针对新型存储介质提供高带宽低时延的IO软件栈，相对传统IO软件栈，软件栈开销降低50%以上。
HSAK用户态IO引擎基于开源的SPDK基础上进行开发：

1. 对外提供统一的接口，屏蔽开源接口的差异。
2. 在开源基础上新增IO数据面增强特性，如DIF功能，磁盘格式化，IO批量下发，trim特性，动态增删盘等特性
3. 提供磁盘设备管理，磁盘IO监测，维测工具等商用特性

## 编译教程

1. 下载hsak源码
   
    $ git clone https://gitee.com/openeuler/hsak.git

2. 编译和运行依赖
   
    hsak的编译和运行依赖于spdk、dpdk、libboundscheck等组件

3. 编译
   
    $ cd hsak
   
    $ mkdir build
   
    $ cd build
   
    $ cmake ..
   
    $ make

## 注意事项

### 运行依赖

### 权限限制

### 使用约束

1. 同一台机器最多使用和管理512个NVMe设备
2. 启用HSAK执行IO相关业务时，需要确保系统有至少500M以上连续的空闲大页内存
3. 启用用户态IO组件执行相关业务时，需要确保硬盘管理组件（ublock）已经启用
4. 启用磁盘管理组件（ublock）执行相关业务时，需确保系统有足够的连续空闲内存，每次初始化ublock组件会申请20MB大页内存
5. 每次运行HSAK之前，产品需要调用setup.sh来配置打野，解绑NVMe设备内核态驱动。
6. 执行libstorage_init_module成功后方可使用HSAK模块提供的其他接口；每个进程仅能执行一次libstorage_init_module调用
7. 执行libstorage_exit_module函数之后不能再使用HSAK提供的其他接口，再多线程场景特别需要注意，在所有线程结束之后再退出HSAK。
8. HSAK ublock组件在一个服务器上只能启动一个服务，且最大支持64个ublock客户端并发访问，ublock服务端处理客户端请求的处理上限是20次/s。
9. HSAK ublock组件必须早于数据面IO组件和ublock客户端启动，HSAK提供的命令行工具也必须在ublock服务端启动后才能执行。
10. 不要注册SIGBUS信号处理函数；spdk针对该信号有单独的处理函数；若该函数被覆盖，会导致spdk注册的SIGBUS处理函数失效，产生coredump

## 使用说明

### nvme.conf.in配置文件

HSAK配置文件默认安装在/etc/spdk/nvme.conf.in，开发人员可以根据实际业务需要对配置文件进行修改，配置文件内容如下：
- [Global]
1. ReactorMask: 指定用于轮询IO的核（16进制，不能指定0核，按bit位从低位到高位，分别表示不同CPU核，如：0x1表示0核，0x6表示1、2两个核，以此类推，本字段最大支持34个字符，去掉表示16进制的0x标记，剩余32个计数字符，每个16进制字符最大是F，可表示4个核，所以最多可以支持32*4=128个核）。
2. LogLevel：HSAK日志打印级别（0：error；1：warning；2：notice；3：info；4：debug）。
3. MemSize：HSAK占用的内存（最小值为500MB）
4. MultiQ：是否在同一个块设备上开启多队列。
5. E2eDif：DIF类型（1：半程保护；2：全程保护），不同厂商的硬盘对DIF支持能力可能不同，具体请参考硬件厂家资料。
6. IoStat：是否使能IO统计开关（Yes\No）
7. RpcServer：是否启动rpc侦听线程（Yes\No）
8. NvmeCUSE：是否启动CUSE功能（Yes\No），开启后在/dev/spdk目录下生成nvme字符设备
- [Nvme]
1. TransportID：指定NVMe控制器的PCI地址和名称，使用格式为：TransportID "trtype:PCIe traddr:0000:09:00.0" nvme0
2. RetryCount：IO失败时的重试次数，0表示不重试，最大255.
3. TimeoutUsec：IO超市时间，0或者不配置该配置项表示不设置超时时间，单位是us。
4. ActionOnTimeout：IO超时行为（None：仅打印信息；Reset：reset控制器；abort：丢弃超时指令），默认None。
- [Reactor]
1. BatchSize：支持批量提交提交IO的个数，默认是8，最大是32.

### 头文件引用

HSAK提供两个对外头文件，开发者在使用HSAK进行开发时需要包含这两个文件：
1. bdev_rw.h：定义了数据面用户态IO操作的宏、枚举、数据结构和接口API。
2. ublock.h：定义了管理面设备管理、信息获取等功能的宏、枚举、数据结构和接口API。

### 业务运行

开发者在进行软件开发编译后，运行前，需要先运行setup.sh脚本程序，用于重新绑定NVMe盘驱动到用户态，该脚本默认安装在：/opt/spdk。
执行如下命令将盘驱动从内核态绑定到用户态，同时预留1024个2M大页：

```shell
[root@localhost ~]# cd /opt/spdk
[root@localhost spdk]# ./setup.sh
0000:3f:00.0 (8086 2701): nvme -> uio_pci_generic
0000:40:00.0 (8086 2701): nvme -> uio_pci_generic
```

执行如下命令将盘驱动从用户态恢复到内核态，同时释放预留的大页：

```shell
[root@localhost ~]# cd /opt/spdk
[root@localhost spdk]# ./setup.sh reset
0000:3f:00.0 (8086 2701): uio_pci_generic -> nvme
0000:40:00.0 (8086 2701): uio_pci_generic -> nvme
```

### 用户态IO读写场景

开发者通过以下顺序调用HSAK接口，实现经由用户态IO通道的业务数据读写：

1. 初始化HSAK UIO模块
    可调用接口libstorage_init_module，完成HSAK用户态IO通道的初始化。

2. 打开磁盘块设备
    可调用libstorage_open，打开指定块设备，如需打开多个块设备，需要多次重复调用。

3. 申请IO内存
    可调用接口libstorage_alloc_io_buf或libstorage_mem_reserve，前者最大可申请单个65K的IO，后者没有限制（除非无可用空间）。

4. 对磁盘进行读写操作
    根据实际业务需要，可调用如下接口进行读写操作：
   
   - libstorage_async_read
   - libstorage_async_readv
   - libstorage_async_write
   - libstorage_async_writev
   - libstorage_sync_read
   - libstorage_sync_write

5. 释放IO内存
    可调用接口libstorage_free_io_buf或libstorage_mem_free，需要与申请时调用的接口对应。

6. 关闭磁盘块设备
    可调用接口libstorage_close，关闭指定块设备，如果打开了多个块设备，则需要多次重复调用接口进行关闭。
   
   | 接口名称                    | 功能描述                                          |
   | ----------------------- | --------------------------------------------- |
   | libstorage_init_module  | HSAK模块初始化接口                                   |
   | libstorage_open         | 打开块设备                                         |
   | libstorage_alloc_io_buf | 从SPDK的buf_small_pool或者buf_large_pool中分配内存。    |
   | libstorage_mem_reserve  | 从DPDK预留的大页内存中分配内存空间                           |
   | libstorage_async_read   | HSAK下发异步IO读请求的接口（读缓冲区为连续buffer）。              |
   | libstorage_async_readv  | HSAK下发异步IO读请求的接口（读缓冲区为离散buffer）。              |
   | libstorage_async_write  | HSAK下发异步IO写请求的接口（写缓冲区为连续buffer）。              |
   | libstorage_async_wrtiev | HSAK下发异步IO写请求的接口（写缓冲区为离散buff）。                |
   | libstorage_sync_read    | HSAK下发同步IO读请求的接口（读缓冲区为连续buffer）。              |
   | libstorage_sync_write   | HSAK下发同步IO写请求的接口（写缓冲区为连续buffer）。              |
   | libstorage_free_io_buf  | 释放所分配的内存到SPDK的buf_small_pool或者buf_large_pool中 |
   | libstorage_mem_free     | 释放libstorage_mem_reserve所申请的内存空间。             |
   | libstorage_close        | 关闭块设备。                                        |
   | libstorage_exit_module  | HSAK模块退出接口                                    |

### 盘管理场景

HSAK包含一组C接口，可以对盘进行格式化、创建、删除namespace操作。

1. 首先需要调用C接口对HSAK UIO组件进行初始化，如果已经初始化过了，就不需要再调用了。
   
   libstorage_init_module

2. 根据业务需要，调用相应的接口进行盘操作，以下接口可单独调用：
   
   - libstorage_create_namespace
   
   - libstorage_delete_namespace
   
   - libstorage_delete_all_namespace
   
   - libstorage_nvme_create_ctrlr
   
   - libstorage_nvme_delete_ctrlr
   
   - libstorage_nvme_reload_ctrlr
   
   - libstorage_low_level_format_nvm
   
   - libstorage_deallocate_block

3. 最后如果退出程序，则需要销毁HSAK UIO，如果还有其他业务在使用，不需要退出，则不用销毁。
   
   libstorage_exit_module
   
   | 接口名称                            | 功能描述                                      |
   | ------------------------------- | ----------------------------------------- |
   | libstorage_create_namespace     | 在指定控制器上创建namespace（前提是控制器具有namespace管理能力） |
   | libstorage_delete_namespace     | 在指定控制器上删除namespace。                       |
   | libstorage_delete_all_namespace | 删除指定控制器上所有namespace。                      |
   | libstorage_nvme_create_ctrlr    | 根据PCI地址创建NVMe控制器                          |
   | libstorage_nvme_delete_ctrlr    | 根据控制器名称销毁NVMe控制器                          |
   | libstorage_nvme_reload_ctrlr    | 根据传入的配置文件自动穿件或销毁NVMe控制器                   |
   | libstorage_low_level_format_nvm | 低级格式化NVMe盘                                |
   | libstorage_deallocate_block     | 告知NVMe盘可释放的块，用于垃圾回收                       |

### 数据面盘信息查询

在HSAK的IO数据面提供一组C接口，用于查询盘信息，上层业务可根据查询到的信息进行相关的业务逻辑处理。

1. 首先需要调用C接口对HSAK UIO进行初始化，如果已经初始化过了，就不需要再调用了。
   
   libstorage_init_module

2. 根据业务需要，调用相应接口进行信息查询，以下接口可单独调用：
   
   - libstorage_get_nvme_ctrlr_info
   
   - libstorage_get_mgr_info_by_esn
   
   - libstorage_get_mgr_smart_by_esn
   
   - libstorage_get_bdev_ns_info
   
   - libstorage_get_ctrl_ns_info

3. 最后如果退出程序，则需要销毁HSAK UIO，如果还有其他业务在使用，不需要退出，则不用销毁
   
   libstorage_exit_module
   
   | 接口名称                            | 功能描述                          |
   | ------------------------------- | ----------------------------- |
   | libstorage_get_nvme_ctrlr_info  | 获取所有控制器信息。                    |
   | libstorage_get_mgr_info_by_esn  | 数据面获取设备序列号（ESN）对应的磁盘的管理信息。    |
   | libstorage_get_mgr_smart_by_esn | 数据面获取设备序列号（ESN）对应的磁盘的SMART信息。 |
   | libstorage_get_bdev_ns_info     | 根据设备名称，获取namespace信息。         |
   | libstorage_get_ctrl_ns_info     | 根据控制器名称，获取所有namespace信息。      |

### 管理面盘信息查询场景

在HSAK的管理面组件ublock提供一组C接口，用于支持在管理面对盘信息进行查询。

1. 首先调用C接口对HSAK ublock服务端进行初始化

2. 根据业务需要，在另一个进程中调用HSAK UIO组件初始化接口。

3. 如果需要多个进程查询盘信息，则初始化ublock客户端

4. 可在ublock服务端进程或客户端进程调用如下接口进行相应的信息查询业务：

5. 对于块设备列表，在获取相应信息后需要调用以下接口进行资源释放：

6. 最后如果退出程序，则需要销毁HSAK ublock模块（服务端和客户端销毁方法相同）。
   
   | 接口名称                         | 功能描述                                                                                                                                              |
   | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
   | init_ublock                  | 初始化ublock功能模块，本接口必须在其他所有ublock接口之前被调用，同一个进程只能初始化一次，原因是init_ublock接口中会初始化DPDK，而DPDK初始胡所分配的内存同进程PID绑定，一个PID只能绑定一块内存，且DPDK没有提供释放这块内存的接口，只能通过进程退出来释放。 |
   | ublock_init                  | 本身是对init_ublock接口的宏定义，可理解为将ublock初始化为需要RPC服务。                                                                                                     |
   | ublock_init_norpc            | 本身是对init_ublock接口的宏定义，可理解为ublock初始化为无RPC服务。                                                                                                       |
   | ublock_get_bdevs             | 业务进程通过调用本接口获取设备列表，获取的设备列表中只有PCI地址，不包含具体设备信息，需要获取具体设备信息，请调用接口ublock_get_bdev。                                                                      |
   | ublock_get_bdev              | 进程通过调用本接口获取具体某个设备的信息，设备信息中包括：设备的序列号、型号、fw版本号信息以字符数组形式保持，不是字符串形式。                                                                                  |
   | ublock_get_bdev_by_esn       | 进程通过调用该接口，根据给定的ESN号获取对应设备的信息，设备信息中：序列号、型号、fw版本号。                                                                                                  |
   | ublock_get_SMART_info        | 进程通过调用本接口获取指定设备的SMART信息。                                                                                                                          |
   | ublock_get_SMART_info_by_esn | 进程通过调用本接口获取ESN号对应设备的SMART信息。                                                                                                                      |
   | ublock_get_error_log_info    | 进程通过调用本接口获取设备的Error log信息。                                                                                                                        |
   | ublock_get_log_page          | 进程通过调用本接口获取指定设备，指定log page的信息。                                                                                                                    |
   | ublock_free_bdevs            | 进程通过调用本接口释放设备列表。                                                                                                                                  |
   | ublock_free_bdev             | 进程通过调用本接口释放设备资源。                                                                                                                                  |
   | ublock_fini                  | 销毁ublock功能模块，本接口将销毁ublock模块以及内部创建的资源，本接口同ublock初始化接口需要配对使用。                                                                                       |

### 日志管理

HSAK的日志当前是通过syslog默认输出到/var/log/messages中，由操作系统的rsyslog服务管理。如果产品需要自定义日志目录，可以通过rsyslog配置。

1. 首先需要在配置文件/etc/rsyslog.conf中增加如下修改：

2. 重启rsyslog服务：
   
   ```shell
   if ($programname == 'LibStorage') then {
       action(type="omfile" fileCreateMode="0600" file="/var/log/HSAK/run.log")
       stop
   }
   ```

3. 启动HSAK进程，日志信息即重定向到对应目录。
   
   ```shell
   sysemctl restart rsyslog
   ```

4. 重定向日志如果需要转储，需要用户在/etc/logrotate.d/syslog文件中手动配置。

## 命令行接口

### 盘信息查询命令

#### 命令格式

```shell
libstorage-list [<commands>] [<device>]
```

#### 参数说明

1. commands: 只有“help”可选，“libstorage-list help”用于显示帮助内容。

2. device: 指定PCI地址，格式如：0000:09:00.0，允许同时多个，中间用空格隔离，如果不设置具体的PCI地址，则命令行列出所有枚举到的设备信息。

#### 注意事项

- 故障注入功能仅限于开发、调试以及测试场景使用，禁止在用户现网使用，否则会引起业务及安全风险。

- 在执行本命令时，管理组件（ublock）服务端必须已经启动，用户态IO组件（uio）未启动或已正确启动均可。

- 对于未被ublock组件和用户态IO组件占用的盘，在本命令执行过程中会被占用，此时如果ublock组件或用户态IO组件尝试获取盘控制权，可能存储设备访问冲突，导致失败。

### 盘切换驱动命令

#### 命令格式

```shell
libstorage-shutdown reset <device> [<device2> ...]
```

#### 参数说明

- reset: 用于对指定盘从uio驱动切换到内核态驱动；

- device: 指定PCI地址，格式如：0000:09:00.0，允许同时多个，中间用空格隔离。

#### 注意事项

- libstorage-shutdown reset命令用于将盘从用户态uio驱动切换到内核态nvme驱动。

- 在执行本命令时，管理组件（ublock）服务端必须已经启动，用户态IO组件未启动或已正确启动均可。

- libstoage-shutdown reset命令为危险动作，请确认在切换nvme设备驱动之前，用户态实例已经停止对nvme设备下发IO，nvme设备上的fd已全部关闭，且访问nvme设备的实例已退出。

### 获取IO统计数据命令

#### 命令格式

```shell
libstorage-iostat [-t <interval>] [-i <count>] [-d <device1,device2,...>]
```

#### 参数说明

- -t: 时间间隔，以秒为单位，最小1秒，最大为3600秒。该参数为int型，如果入参值超过int型上限，将被截断成负数或者正数。

- -i: 收集次数，最小为1，最大为MAX_INT次，如果不设置，默认以时间间隔持续收集。该参数为int型，如果入参超过int型上限，将被截断成负数或者正数。

- -d：指定块设备名称（eg：nvme0n1，其依赖于/etc/spdk/nvme.conf.in中配置的控制器名称），可以通过本参数收集指定一个或多个设备性能数据，如果不设置本参数，则收集所有识别到的设备性能数据。

#### 注意事项

- IO统计配置项已使能。

- 进程已经通过用户态IO组件对所需要查询性能信息的盘下发IO操作。

- 如果当前环境上没有任何设备被业务进程占用下发IO，则该命令将在提示：You cannot get iostat info for nvme device no deliver io后退出。

- 在磁盘打开多队列情况下，IO统计工具将该磁盘上多队列的性能数据汇总后统一输出。

- IO统计工具最多支持8192个磁盘队列的数据记录。

- IO统计数据输出结果如下：
  
  | Device | r/s     | w/s     | rKB/s   | wKB/s   | avgrq-sz     | avgqu-sz  | r_await   | w_await   | await      | svctm        | util% | poll-n |
  | ------ | ------- | ------- | ------- | ------- | ------------ | --------- | --------- | --------- | ---------- | ------------ | ----- | ------ |
  | 设备名称   | 每秒读IO个数 | 每秒写IO个数 | 每秒读IO字节 | 每秒写IO字节 | 平均下发IO大小（字节） | 磁盘排队的IO深度 | IO读时延（us） | IO写时延（us） | 读写平均时延（us） | 单个IO处理时延（us） | 设备利用率 | 轮询超时次数 |

## 盘读写命令

#### 命令格式

```shell
libstorage-rw <COMMAND> <device> [OPTIONS...]
```

#### 参数说明

- COMMAND参数
  
  1. read，从设备读取指定的逻辑块到数据缓存区（默认是标准输出）。
  
  2. write，将数据缓存区（默认是标准输入）的数据写入到NVMe设备的指定逻辑块。
  
  3. help，显示该命令行的帮助信息。

- device: 指定PCI地址，格式如：0000:09:00.0。

- OPTIONS参数
  
  1. --start-block，-s：读写逻辑块的64位首地址（默认值为0）。
  
  2. --block-count，-c：读写逻辑块的数量（从0开始计数）。
  
  3. --data-size，-z：读写数据的字节数。
  
  4. --namespae-id，-n：设备的namespace id（默认id值是1）。
  
  5. --data，-d：读写用的数据文件（读时保存读出的数据，写时提供写入数据）。
  
  6. --limited-retry，-l：设备控制器进行有限次数的重启来完成设备读写。
  
  7. --force-unit-access，-f：确保指令完成之前从非易失介质中完成读写。
  
  8. --show-command，-v：发送读写命令之前显示指令相关信息。
  
  9. --dry-run，-w：仅显示读写指令相关信息，不进行实际读写操作。
  
  10. --latency，-t：统计命令行端到端读写的时延。
  
  11. --help，-h：显示相关命令的帮助信息。

## 参与贡献

1. Fork本仓库
2. 新建个人分支
3. 提交代码
4. 新建Pull Request
