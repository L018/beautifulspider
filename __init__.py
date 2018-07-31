#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# author: zero
# Date: 2017/10/26 20:40

"""
极尽可能的模拟真实请求，维护好 url ip port ua cookies 请求优先级等所有相关数据。
engine 首先获取第一url及要求，查找 对应 url 解析规则，自动化处理程序，允许通过后会生成一个自定义 url 对象(感觉元组可以)交给 schedule，
"""