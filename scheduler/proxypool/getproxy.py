#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# author: zero
# Date: 2017/10/27 10:50

"""
getproxy 模块用来获取代理 ip，可以单独存在，单独运行，不应再导入 beautifulspider 中任何东西，降低耦合度。
getproxy 模块通过获取代理的关键函数采用协程返回，能够持续保存状态，不存在重新运行状态。
getproxy 模块自动维护一个 ip 池，能够迅速对请求进行响应。
"""

import requests
import re
import json
import copy

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0',
           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
           'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
           'Accept-Encoding': 'gzip, deflate',
           'Connection': 'keep-alive',
           'Referer': 'http://www.baidu.com/'}  # 多线程或多进程 copy 变量 headers


def coroutine(func):
    """协程装饰器，自动执行 .next()方法。"""
    def start(*args, **kwargs):
        g = func(*args, **kwargs)
        g.__next__()
        return g
    return start


class Getproxy(object):
    """
    获取 ip 代理主模块，每一个网站分为 get_XX_proxy 和 parser_XX_html 两部分。
    主程序为 run() 函数。
    """

    def parser_xici_html(self, html):
        """解析 xicidaili 网页数据，返回 ip 列表"""
        proxy_list = []
        re_list_ip = re.findall(r'<td>\d*\.\d*\.\d*\.\d*</td>', html)
        re_list_port = re.findall(r'<td>\d{1,5}</td>', html)
        re_list_protocol = re.findall(r'<td>HTTPS?</td>', html)
        re_list_city = re.findall(r'(?s)(?<=<td>(?=\d{1,5}</td>)).*?(?=<td class="country">高匿</td>)', html)
        l = len(re_list_ip)
        for i in range(l):
            proxy_ip = re_list_ip[i].replace('<td>', '').replace('</td>', '')
            proxy_port = re_list_port[i].replace('<td>', '').replace('</td>', '')
            proxy_protocol = re_list_protocol[i].replace('<td>', '').replace('</td>', '')
            try:
                proxy_city = re.findall(r'[\u4e00-\u9fa5]+', re_list_city[i])[0]  # 提取汉字
            except Exception:
                proxy_city = ''
            # args元组修改，将影响之后所有涉及元组取值问题
            args = (proxy_ip,
                    proxy_port,
                    proxy_protocol.lower(),
                    'get',
                    '高匿',
                    'China',
                    proxy_city,
                    'xicidaili')
            print(args)
            proxy_list.append(args)
        return proxy_list

    @coroutine
    def get_xici_proxy(self):
        """通过 yield 决定获取 proxy 的 page 页，通过 yield 表达式返回 ip 列表。send(None)结束该函数"""
        url = 'http://www.xicidaili.com/nn/'
        session = requests.Session()
        headers = HEADERS.copy()
        headers['Referer'] = url
        headers['Host'] = 'www.xicidaili.com'
        result = []
        while True:
            page = (yield result)  # send 获取 page, 返回 result
            if page == None:  # 设置标识位，以结束该获取函数
                break
            elif page == 1:
                html = session.get(url, headers=headers, timeout=(6, 18))
            else:
                headers['Referer'] = url + str(page-1)  # 尽量模拟真实逻辑
                html = session.get(url + str(page), headers=headers, timeout=(6, 18))
            try:
                html.raise_for_status()
            except Exception:
                print(url + str(page) + '请求失败！')
                result = []  # 请求失败，返回结果为[](空列表)
                continue
            result = self.parser_xici_html(html.text)

    def parser_gather_html(self, html):
        """解析 gather 网页数据，返回 ip 列表"""
        re_str = 'insertPrx\(.*\}'
        proxy_list = []
        html_list = re.findall(re_str, html)
        for pl in html_list:
            p = json.loads(pl[10:])
            # args元组修改，将影响之后所有涉及元组取值问题
            args = (p['PROXY_IP'],
                    str(int(p['PROXY_PORT'], 16)),
                    'http',  # 没有指明的情况下，默认是仅支持http协议
                    'get',  # 没有指明的情况下，默认是仅支持get请求
                    p['PROXY_TYPE'],
                    p['PROXY_COUNTRY'],
                    p['PROXY_CITY'],
                    'gatherproxy')
            proxy_list.append(args)
        return proxy_list

    @coroutine
    def get_gather_proxy(self):
        """通过 yield 决定获取 proxy 的 page 页，通过 yield 表达式返回 ip 列表。send(None)结束该函数"""
        url = 'http://www.gatherproxy.com/proxylist/country/?c=China'
        session = requests.Session()
        headers = HEADERS.copy()
        headers['Referer'] = 'http://www.gatherproxy.com/proxylistbycountry'
        headers['Host'] = 'www.gatherproxy.com'
        result = []
        while True:
            page = (yield result)  # send 获取 page, 返回 result
            if page == None:  # 设置标识位，以结束该获取函数
                break
            elif page == 1:
                html = session.get(url, headers=headers, timeout=(6, 18))
            try:
                html.raise_for_status()
            except Exception:
                print('gather 网站特殊，拒绝请求其他页面，请等待 30min 重新请求。')
                result = []  # 拒绝请求，返回结果为[](空列表)
                continue
            result = self.parser_xici_html(html.text)

    @staticmethod
    def test_firewall():
        """静态方法，测试防火墙能否访问外网。return True or False"""
        firewall = 0
        try:
            print('正在测试是否可以翻墙，请耐心等待···')
            requests.get('http://www.google.com/', headers=HEADERS, timeout=(6, 18)).raise_for_status()
            firewall += 1
            requests.get('http://www.youtube.com/', headers=HEADERS, timeout=(6, 18)).raise_for_status()
            firewall += 1
        except Exception:
            pass
        if firewall > 0:
            print('测试成功，可以访问外网。')
            return True
        print('测试失败，拒绝访问外网。')
        return False

    def run(self, pool=None, cv=None, poolsize=100):
        """Getproxy 模块主运行程序，poolsize 表示当前模块维护的 ip 池应当大小，也为共享对象 pool 列表的大小(Max500)。
        必须以线程的方式运行(基于线程共享对象、条件变量)，条件变量进行加锁及通知。自动测试是否可以翻墙。"""
        my_pool = []
        if poolsize > 500:
            poolsize = 500
        in_firewall = (self.get_xici_proxy,)
        no_firewall = (self.get_xici_proxy, self.get_gather_proxy)
        if self.test_firewall():
            proxy_tuple = no_firewall
        else:
            proxy_tuple = in_firewall
        page_num = 1
        # 准备好维护的 ip 池 my_pool
        while True:
            for i in proxy_tuple:
                my_pool.extend(i().send(page_num))
            page_num += 1
            if len(my_pool) >= poolsize * 2:
                break
        while True:
            try:
                cv.acquire()
                while len(pool) > 0:  # 防止多线程时多个线程被唤醒，但是等待的条件已经消失
                    cv.wait()
                pool = copy.deepcopy(my_pool[:poolsize])
                del my_pool[:poolsize]
                cv.notify()  # 唤醒消费者线程
                cv.release()
            except Exception:
                pass
            finally:  # 确保异常后能够释放锁，避免死锁。
                cv.release()
            while True:
                if len(my_pool) >= poolsize * 2:  # 防止几轮过后 my_pool 越来越大
                    break
                for i in proxy_tuple:
                    my_pool.extend(i().send(page_num))
                page_num += 1