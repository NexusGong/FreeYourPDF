# -*- coding: utf-8 -*-
"""
PDF 检测与解锁后端：仅提供 API，与前端分开启动；需配置 CORS。
"""
import io
from flask import Flask, request, jsonify, send_file
from pypdf import PdfReader, PdfWriter

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB


@app.after_request
def _cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp


@app.before_request
def _cors_preflight():
    if request.method == 'OPTIONS':
        return '', 204
    return None

# 常见密码 + 1～4 位数字，用于暴力破解
COMMON_PASSWORDS = [
    '', '123456', 'password', '12345678', '1234', '12345', 'qwerty', '123456789',
    '1234567', '111111', '000000', '123123', 'abc123', 'password1', 'admin', 'root',
    'pdf', 'PDF', 'Pdf', 'pass', 'Pass', 'open', 'Open', 'secret', 'changeme'
]


def _password_list():
    seen = set()
    out = []
    for p in COMMON_PASSWORDS:
        if p not in seen:
            seen.add(p)
            out.append(p)
    for length in range(1, 5):
        for n in range(10 ** length):
            s = str(n).zfill(length)
            if s not in seen:
                seen.add(s)
                out.append(s)
    return out


def _can_open(stream, password=None):
    """尝试用给定密码打开 PDF，成功返回 True。"""
    stream.seek(0)
    try:
        reader = PdfReader(stream)
        if not reader.is_encrypted:
            return True
        pwd = password if password is not None else ''
        reader.decrypt(pwd)
        return len(reader.pages) > 0
    except Exception:
        return False


def _has_encrypt_in_bytes(data):
    return b'/Encrypt' in data


@app.route('/api/detect', methods=['POST'])
def api_detect():
    """检测 PDF：是否需要打开密码、是否有权限限制。"""
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': '请上传 PDF 文件'}), 400
    data = f.read()
    stream = io.BytesIO(data)
    has_encrypt_meta = _has_encrypt_in_bytes(data)
    encrypted = True
    has_restrictions = False
    if has_encrypt_meta:
        if _can_open(stream, ''):
            encrypted = False
            has_restrictions = True
    if encrypted:
        if _can_open(stream, None):
            encrypted = False
            has_restrictions = has_encrypt_meta
        elif _can_open(stream, ''):
            encrypted = False
            has_restrictions = True
    return jsonify({'encrypted': encrypted, 'hasRestrictions': has_restrictions})


@app.route('/api/unlock', methods=['POST'])
def api_unlock():
    """解除权限或解密：上传 PDF，可选密码，返回解锁后的 PDF。"""
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': '请上传 PDF 文件'}), 400
    password = request.form.get('password') or ''
    data = f.read()
    stream = io.BytesIO(data)
    try:
        reader = PdfReader(stream)
        if reader.is_encrypted:
            reader.decrypt(password)
        # 逐页复制到新文档，避免 clone_from 对部分 PDF 不兼容
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        out = io.BytesIO()
        writer.write(out)
        out.seek(0)
        return send_file(
            out,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=(f.filename or 'output.pdf').replace('.pdf', '_unlocked.pdf')
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': '解锁失败：' + str(e)}), 400


@app.route('/api/crack-and-unlock', methods=['POST'])
def api_crack_and_unlock():
    """暴力破解打开密码后解锁，返回解锁后的 PDF 或错误。"""
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': '请上传 PDF 文件'}), 400
    data = f.read()
    stream = io.BytesIO(data)
    passwords = _password_list()
    for pwd in passwords:
        stream.seek(0)
        try:
            reader = PdfReader(stream)
            if not reader.is_encrypted:
                break
            reader.decrypt(pwd)
            if len(reader.pages) > 0:
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)
                out = io.BytesIO()
                writer.write(out)
                out.seek(0)
                return send_file(
                    out,
                    mimetype='application/pdf',
                    as_attachment=True,
                    download_name=(f.filename or 'output.pdf').replace('.pdf', '_unlocked.pdf')
                )
        except Exception:
            continue
    return jsonify({'error': '未能破解密码'}), 400


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
