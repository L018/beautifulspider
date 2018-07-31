#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# author: zero
# Date: 2017/10/27 10:49

"""
clearproxy 模块用来对 getproxy 模块产生的 ip 进行验证清理，
可验证 可用性、高匿性、http/https/socks5、get/post
# 同时可以选择是否接入 database ，可以获取数据库中的 ip 以及将 清洗后的 ip 写入数据库，
选择接入数据库：首先从数据库中获取数据进行重新验证(时间限定内)，同时会开启线程获取代理，
当代理够用时，会不停歇的清洗数据库，剔除无效数据。
所有验证通过的上传给scheduler的 ip 都会保存在数据库中，失败的 ip 会进行回传。
测试方式选择单个测试，提高灵活性

改进：
很多地方可以使用异步非阻塞模式，提高效率
在与数据库结合方面，灵活性不够好，效率上也不行，比如清洗数据库的同时查询返回，逻辑一定不正确，太复杂了
"""

import requests
import threading
import copy
import concurrent.futures
import pymysql
import time
import multiprocessing


from getproxy import Getproxy as gp

Lock = threading.Lock() # 双重检查锁定检测实例是否存在
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0',
           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
           'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
           'Accept-Encoding': 'gzip, deflate',
           'Connection': 'keep-alive',
           'Upgrade-Insecure-Requests': '1'}


class Clearproxy(object):
    """Clearproxy 类，测试函数为 XX_test()
    主程序为 run() 函数。"""

    def ok_test(self, ip, port, protocol, method, id=None):
        """测试可用性 对 www.baidu.com 和 httpbin.org 多次打靶 
        return (ip, port, protocol, method, id)元组 or None, 
        添加 id 只是为了方便数据库操作，此函数没有涉及 id 的地方, 默认设置为None"""
        ptc = ''
        if protocol.lower() == 'socks5':  # 如果是 socks5 默认使用可 https
            ptc = 'https'
        else:
            ptc = protocol.lower()
        proxies = {'http': 'socks5' if protocol.lower() == 'socks5' else 'http' + '://' + ip + ':' + port,
                   'https': 'socks5' if protocol.lower() == 'socks5' else 'http' + '://' + ip + ':' + port}
        # 测试 GET
        if method.lower() == 'get':
            # 四次打靶，通过三次即通过
            ok_times = 0
            if protocol.lower() in ('http', 'https', 'socks5'):
                for _ in range(2):
                    try:
                        # timeout 的设定影响着线程池 timeout 的设定
                        requests.get(ptc + '://www.baidu.com/',
                                     headers=HEADERS,
                                     proxies=proxies,
                                     timeout=(3,12)).raise_for_status()
                        ok_times += 1
                        requests.get(ptc + '://httpbin.org/get',
                                     headers=HEADERS,
                                     proxies=proxies,
                                     timeout=(3, 12)).raise_for_status()
                        ok_times += 1
                    except Exception:
                        pass
                if ok_times >= 3:
                    return (ip, port, protocol, method, id)
                else:
                    return None
            # 协议错误
            else:
                return None
        # 测试 POST
        else:
            # 三次打靶，通过二次即通过
            ok_times = 0
            if protocol.lower() in ('http', 'https', 'socks5'):
                for _ in range(3):
                    try:
                        # timeout 的设定影响着线程池 timeout 的设定
                        requests.post(ptc + '://httpbin.org/anything',
                                     headers=HEADERS,
                                     proxies=proxies,
                                     timeout=(3, 12)).raise_for_status()
                        ok_times += 1
                    except Exception:
                        pass
                if ok_times >= 2:
                    return (ip, port, protocol, method, id)
                else:
                    return None
            # 协议错误
            else:
                return None

    def anonymity_test(self, id, ip, port, protocol, method):
        """测试 ip 代理的高匿性，测试高匿性应该在测试完 ip 可用之后再进行。
        return (ip, port, protocol, method, id)元组 or None, 
        添加 id 只是为了方便数据库操作，此函数没有涉及 id 的地方, 默认设置为None"""
        # http://www.xdaili.cn/monitor  http://www.ip138.com/
        # http://www.xdaili.cn/ipagent//checkIp/ipList?ip_ports%5B%5D=27.219.36.127%3A8118  http://2017.ip138.com/ic.asp

    def clean(self):
        """采用线程池，对单独的测试做一个整合，减少冗余
        使用带返回协程，一次不间断运行
        send 元组列表 [(ip, port, protocol, method, id),]，添加 id 只是为了方便数据库操作，此函数没有涉及 id 的地方"""
        cleaned = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            while True:
                iterable = (yield cleaned)
                fs = [executor.submit(self.ok_test, l[0], l[1], l[2], l[3], l[4]) for l in iterable]
                try:
                    for future in concurrent.futures.as_completed(fs, 100):  # timeout 的设定与线程池中每一个 timeout 有关
                        try:
                            if future.result() != None:
                                cleaned.append(future.result())
                        except Exception as exc:
                            print('一 ip 可用性测试 generated an exception: %s' % exc)
                except concurrent.futures.TimeoutError as e:
                    print('generated an exception: %s' % e)

    def clean_database(self, conn):
        """
        清洗整个数据库
        :return: True or False
        """
        if conn == None:
            print("MyError: conn is not usable.")
            return False
        cursor = conn.cursor()
        self.clean().__next__()
        i = 0
        while True:
            if (cursor.execute('select ip, port, protocol, method, id from proxy limit ' + str(i*50) +',50') > 0):
                result1 = cursor.fetchall()
                result2 = self.clean().send(result1)
                result_set = set(result1) - set(result2)
                for s in result_set:
                    cursor.execute('update proxy set leveltimes = -1 where id = ' + str(s[4]))
                conn.commit()
            else:
                break
            i += 1
        cursor.execute('delete from proxy where leveltimes < 0')  # leveltimes 小于 0 表示无效数据
        cursor.close()
        conn.commit()
        return True

    def run(self, ip_list, pipe):
        """通过 ip_list[(ip, port),] 在进程间通信，对 pipe 接受的字符串数据，以 “|” 分割后产生 num protocol method ，
        分别表示代理的数量、协议及提交方法的要求 num 最大允许值为 150
        如果接收到的是 None ，代表结束进程"""
        ds = Datasource()
        conn = ds.get_conn()
        if conn is None:
            print("Error: Datasource().get_conn() is Failed.")
        # cleaned_pool = []  # 一个固定大小的清理完毕的代理池，清洗后多余数据写入数据库或暂停清洗。
        received_pool = []  # 接受 ip 池，是线程之间的共享对象，除 get() 方法不可操作
        cv = threading.Condition()  # 条件变量
        t = threading.Thread(target=gp().run, args=(received_pool, cv, 100))
        t.daemon = True  # 后台进程，随创建进程结束而结束，不允许创建子进程
        t.start()

        def get(received_pool, cv):
            """向线程 t 获取代理，返回获取列表"""
            result = []
            try:
                cv.acquire()
                while len(received_pool) == 0:  # 防止多线程时多个线程被唤醒，但是等待的条件已经消失
                    cv.wait()
                result = copy.deepcopy(received_pool)
                del received_pool[:]
                cv.notify()  # 唤醒生产者线程
                cv.release()
            except Exception:
                print("MyError: 清洗线程获取代理异常。当前线程：cleanproxy线程")
                pass
            finally:  # 确保异常后能够释放锁，避免死锁。
                cv.release()
            return result

        # 1.将数据库彻底清洗一遍，
        self.clean_database(conn)
        # 2.向 6 个列表填入数据, 维持在150左右 只有 ip port 没有其他多余数据
        http_get_list = []
        https_get_list = []
        socks5_get_list = []
        http_post_list = []
        https_post_list = []
        socks5_post_list = []
        # 记录数据库所查到最后一条记录的 id
        http_get_id = 0
        https_get_id = 0
        socks5_get_id = 0
        http_post_id = 0
        https_post_id = 0
        socks5_post_id = 0
        cursor = conn.cursor()
        for p in ('http', 'https', 'socks5'):
            for m in ('get', 'post'):
                # leveltimes 大于等于 200 表示新插入数据库中的数据
                sql = 'select id,ip, port from proxy where protocol = %s and method = %s and leveltimes < 200 limit 150'
                cursor.execute(sql,(p, m))
                r = cursor.fetchall()
                l = locals()[p + '_' + m + '_list']  # eval(p + '_' + m + '_list')
                for i in r:
                    l.append((i[1], i[2]))
                max_id = locals()[p + '_' + m + '_id']  # eval(p + '_' + m + '_id')
                if len(r) == 150:
                    max_id = r[-1][0]
                else:
                    max_id = -1  # 设置无需再使用数据库获取代理的标志
        # 此时列表中数据可能放满，也可能未满，数据库中的数据可能已经用完，也可能还有
        # 3.取数据
        massage = pipe.recv()
        if massage is None:  # 代表结束进程
            pipe.close()
            ds.return_conn(conn)
            ds.close()
            return
        self.clean().__next__()  # 建立清洗协程
        while True:
            msg = massage.split('|')
            num = msg[0]
            # 设置 num 最大允许值为 150
            if num > 150:
                num = 150
            protocol = msg[1]
            method = msg[2]
            if protocol not in ('http', 'https', 'socks5') and method not in ('get', 'post'):
                pipe.send(None)  # 表示接受信息出错，需要重新发送
                massage = pipe.recv()
                if massage is None:
                    pipe.close()
                    ds.return_conn(conn)
                    ds.close()
                    return
                continue
            pml = locals()[protocol + '_' + method + '_list']
            pm_id = locals()[protocol + '_' + method + '_id']
            # 取之前保证数据量满足 num 大小要求
            # 立一个 flag ，学会拒绝，10 次之后如果依旧不能满足 num 数量要求，则放弃抓取
            flag = 0
            while len(pml) < num and flag < 10:
                if pm_id > 0:  # 数据库还有可取数据
                    sql = 'select id, ip, port from proxy where protocol = %s and method = %s and leveltimes < 200 limit %d,150'
                    cursor.execute(sql, (protocol, method, pm_id))
                    r = cursor.fetchall()
                    for i in r:
                        pml.append((i[1], i[2]))  # 对应维护列表添加 ip port
                    if len(r) == 150:
                        pm_id = r[-1][0]
                    else:
                        pm_id = -1  # 设置无需再使用数据库获取代理的标志
                else:  # 没有可用数据，需要去爬取
                    flag += 1
                    got_list = get(received_pool, cv)
                    i = 0  # 为每条数据编号
                    send_clean_list = []  # 发送到清洗线程池的数据列表
                    for r in got_list:
                        send_clean_list.append((r[0], r[1], r[2], r[3], i))  # 假 id
                        i += 1
                    cleaned_list = self.clean().send(send_clean_list)
                    id_list = []
                    for j in cleaned_list:
                        id_list.append(j[4])  # 获取清洗过的编号
                        pml.append(j[0], j[1])  # 为维护列表添加清晰完成的数据
                    # 将清洗完成的数据写入数据库并且设置 leveltimes 为 200
                    for j in id_list:
                        cursor.execute('insert into proxy values(null,%s,%s,%s,%s,%s,%s,%s,%s,200)',got_list[j])
                        conn.commit()  # 提交数据
            # 已经尽最大努力满足数量要求了，可能依旧小于 num
            real_num = num if len(pml) > num else len(pml)
            ip_list = copy.deepcopy(pml[:real_num])
            pipe.send('OK')  # 发送 OK 通知获取程序已发送，可以取走了
            massage = pipe.recv()
            if massage is None:  # 代表结束进程
                pipe.close()
                ds.return_conn(conn)
                ds.close()
                return


class Datasource(object):
    """
    数据库连接池
    """
    pool = []
    lock_get = threading.Lock()

    def __new__(cls, *args, **kw):
        """构建单例模式"""
        if not hasattr(cls, '_instance'):
            try:
                Lock.acquire()
                if not hasattr(cls, '_instance'):
                    orig = super(Datasource, cls)
                    cls._instance = orig.__new__(cls, *args, **kw)
            finally:
                Lock.release()
        return cls._instance

    def __init__(self):
        if len(self.pool) == 0:
            # 建立 5 个连接的连接池
            for i in range(5):
                conn = pymysql.connect('localhost','root','root','proxy',charset='utf8')
                # TODO: 发布时将登陆名密码改为常见的 ‘root’
                self.pool.append(conn)

    def get_conn(self):
        """获取连接池连接"""
        conn = None
        try:
            self.lock_get.acquire()
            if len(self.pool) > 0:
                conn = self.pool.pop(0)
            else:
                time.sleep(10) # 等待 10s
                if len(self.pool) > 0:
                    conn = self.pool.pop(0)
                else:
                    conn = None
        finally:
            self.lock_get.release()
        return conn

    def return_conn(self, conn):
        """将 conn 归还给连接池"""
        self.pool.append(conn)

    def close(self):
        """关闭连接及连接池"""
        for i in self.pool:
            i.close()


if __name__ == '__main__':
    iplist = []
    pl = Clearproxy()
    conn1, conn2 = multiprocessing.Pipe()
    p = multiprocessing.Process(target=pl.run, args=(iplist, conn2))
    p.start()
    conn1.send('50|http|get')
    if conn1.recv() == 'OK':
        print(iplist)