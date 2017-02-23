#encoding='utf-8'
#导入所需模块
import os
import random
from flask import Flask, render_template, redirect, url_for, flash, abort, session, request, jsonify, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, ValidationError, RadioField
from wtforms.validators import Email, DataRequired, Length, EqualTo
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from threading import Thread
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

#创建应用实例
app = Flask(__name__)

#配置表单密令
SECRET_KEY='\xfe{\xa9\n\x1b0\x16\xcfF\xb103\x9d)\xdf\xfd\xab\xd8\x9b\xbf\xf2\xf5\xb0\x86'

#数据库配置
basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')	#数据库URI		
SQLALCHEMY_COMMIT_ON_TEARDOWN = True	#更改自动提交
SQLALCHEMY_TRACK_MODIFICATIONS = True

#邮件配置
MAIL_SERVER = 'smtp.qq.com'	#邮件服务器
MAIL_PORT = 465	#端口
MAIL_USE_SSL = True		
MAIL_USERNAME = '1312533774@qq.com'	#邮箱账号
MAIL_PASSWORD = 'wodspmlyvxljhhia'	#邮箱密码

#应用配置
app.config.from_object(__name__)

#实例化所需模块
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
mail = Mail(app)
manager = Manager(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

#异步发送邮件
def send_async_mail(app, msg):
	with app.app_context():
		mail.send(msg)

def send_mail(to, sub, link):
	msg = Message('Flasky邮件来啦', sender=('Flasy', '1312533774@qq.com'), recipients=[to])
	msg.body = sub + link
	msg.html = '<h1>' + sub + '</h1><a href=' + link + '>' + link + '</a>'
	thr = Thread(target=send_async_mail, args=[app, msg])
	thr.start()
	return thr

#管理员表单模型
class AdminForm(FlaskForm):
	#邮箱验证
	def account_check(self, field):
		if field.data != 'huster1446@admin.com':
			raise ValidationError('你可能是假的管理员')
	#密码验证
	def password_check(self, field):
		if field.data != 'huster1446':
			raise ValidationError('你可能是假的管理员')

	email = StringField("管理员邮箱", validators=[DataRequired(message='邮箱是空的请加油'), 
		Email(message=u'不是邮箱'), account_check])
	password = PasswordField("管理员密码", validators=[DataRequired(message='密码忘了哦'), password_check])
	login = SubmitField("有请最牛逼的管理员登录")

#管理员增加用户表单模型
class AdminAddForm(FlaskForm):
	#检测邮箱唯一性
	def email_unique(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('邮箱存在')

	name = StringField('用户名', validators=[DataRequired()])
	email = StringField('用户邮箱', validators=[DataRequired(), email_unique])
	password = StringField('用户密码', validators=[DataRequired()])
	role = RadioField('身份', choices=[('学生', '学生'), ('教师', '教师')], default='学生')
	add = SubmitField("增加用户")
			
#用户登录表单模型
class LoginForm(FlaskForm):
	#验证用户是否存在
	def email_exist(self, field):
		if not User.query.filter_by(email=field.data).first():
			raise ValidationError('这邮箱不能用啊')
	
	email = StringField("邮箱", validators=[DataRequired(message='邮箱是空的请加油'), 
		Email(message=u'你这是邮箱吗?'), email_exist])
	password = PasswordField("密码", validators=[DataRequired(message='密码都没有咋登录')])
	login = SubmitField("登录")

#用户注册表单模型
class SignupForm(FlaskForm):
	def email_unique(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('为啥用人家的邮箱?')
	#检测密码中是否有空格
	def password_noblank(self, field):
		for s in field.data:
			if s == ' ':
				raise ValidationError('不要搞事情!')

	name = StringField('姓名', validators=[DataRequired(message='必填')])
	email = StringField("邮箱", validators=[DataRequired(message='连邮箱都没有?'), 
		Email(message='神TM邮箱'), email_unique])
	password = PasswordField("密码", validators=[DataRequired(message='密码不设置的?'),
		Length(6, message='这么短?'), password_noblank])		
	confirm = PasswordField("确认密码", validators=[DataRequired(message='确认一下是好的'),
		EqualTo('password', "两次密码不一样!")])
	role = RadioField('身份', choices=[('学生', '学生'), ('教师', '教师')], default='教师')
	signup = SubmitField("注册")

#找回密码表单模型
class ForgetForm(FlaskForm):
	def email_exist(self, field):
		if not User.query.filter_by(email=field.data).first():
			raise ValidationError('没有这个邮箱')
	def password_noblank(self, field):
		for s in field.data:
			if s == ' ':
				raise ValidationError('搞事情!')

	email = StringField("注册时邮箱", validators=[DataRequired(message='邮箱不能为空'), 
		Email(message='这也叫邮箱?'), email_exist])
	password = PasswordField("密码", validators=[DataRequired(message='密码不能为空'),
		Length(6, message='密码搞这么短干嘛?'), password_noblank])		
	confirm = PasswordField("确认密码", validators=[DataRequired(message='密码不能为空'),
		EqualTo('password', "两次密码不一致")])
	getback = SubmitField("确认")	

#教师新增学生表单模型
class AddForm(FlaskForm):
	#检测学号是否存在
	def student_exist(self, field):
		user = User.query.filter_by(id=session.get('user_id')).first()
		for student in user.students:
			if student.stu_id == field.data:
				raise ValidationError("该学号学生已存在")

	stu_id = StringField("学生学号", validators=[DataRequired(message="这能空?"), Length(6, 15, "有点短?有点长?"), student_exist])
	name = StringField("学生姓名", validators=[DataRequired(message="这能空?"), Length(-1, 10, "名字过长")])
	cls = StringField("专业班级", validators=[DataRequired(message="没有数据不好交差"), Length(-1, 15, "精简一下")])
	addr = StringField("所在寝室", validators=[DataRequired(message="没有数据不好交差"), Length(-1, 15, "字太多了")])
	phone = StringField("联系方式", validators=[DataRequired(message="没有数据不好交差")])
	add = SubmitField("添加吧皮卡丘!")

#教师搜索学生表单模型
class SearchForm(FlaskForm):
	keyword = StringField("输入查询关键字", validators=[DataRequired(message="输入不能为空")])
	search = SubmitField("Find It!")
		
#用户模型
class User(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64))
	email = db.Column(db.String(64), index=True, unique=True)
	password = db.Column(db.String(64))
	#身份
	role = db.Column(db.String(64), default='学生')
	#验证邮箱码
	active_code = db.Column(db.String(10))
	#激活状态
	active_state = db.Column(db.Boolean, default=False)
	#所管理的学生
	students = db.relationship('Student', backref='user', lazy='dynamic')
	#冻结状态
	frozen = db.Column(db.Boolean, default=False)

#学生模型
class Student(db.Model):
	__tablename__ = 'students'
	id = db.Column(db.Integer, primary_key=True)
	stu_id = db.Column(db.String(64), index=True)
	name = db.Column(db.String(64))
	#班级
	cls = db.Column(db.String(64))
	#寝室
	addr = db.Column(db.String(64))
	phone = db.Column(db.String(64))
	#教师id
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

#初始化数据库
db.create_all()

#登录路由控制
@app.route('/', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		#验证是否被冻结
		if user.frozen:
			flash("你的账户已被冻结")
			return redirect(url_for('login'))
		#验证是否激活邮箱
		if user.active_state == False:
			flash("请查收邮件以完成注册")
			return redirect(url_for('login'))
		#验证密码是否正确
		elif user.password != form.password.data:
			flash("密码不正确")
			return redirect(url_for('login'))
		#记住登录状态
		session['user_id'] = user.id
		#根据身份重定向
		if user.role == '教师':
			return redirect('/u/' + str(user.id))
		if user.role == '学生':
			return redirect('/s/' + str(user.id))
	return render_template('form.html', form=form)

#退出路由控制
@app.route('/logout')
def logout():
	#管理员退出
	if session.get('admin'):
		session['admin'] = None
	#普通用户退出
	elif session.get('user_id') is None:
		flash("未登录")
		return redirect(url_for('login'))
	flash("退出成功")
	session['user_id'] = None
	return redirect(url_for('login'))

#注册路由控制
@app.route('/signup', methods=['GET', 'POST'])
def signup():
	form = SignupForm()
	if form.validate_on_submit():
		#生成随机码
		n = []
		for i in range(10):
			n.append(str(random.randint(0, 9)))
		active_code = ''.join(n)
		#实例化用户
		new_user = User(name=form.name.data, email=form.email.data, password=form.password.data,
			role=form.role.data, active_code=active_code)
		#新增用户
		db.session.add(new_user)

		#发送验证邮件
		user = User.query.filter_by(email=form.email.data).first()
		sub = "请点击下方链接继续完成注册："
		link = 'www.hustljh.cn/c/' + str(user.id) + '/' + active_code
		send_mail(new_user.email, sub, link)
		
		flash("请查收邮件以继续完成注册")
		return redirect(url_for('login'))
	return render_template('form.html', form=form)

#验证邮箱路由控制
@app.route('/c/<int:id>/<active_code>')
def check(id, active_code):
	user = User.query.filter_by(id=id).first()
	#验证随机码是否匹配
	if user is not None and user.active_code == active_code:
		user.active_state = True
		db.session.add(user)
		return render_template('success.html', action="注册")
	abort(400)

#找回密码路由控制
@app.route('/forget', methods=['GET', 'POST'])
def forget():
	form = ForgetForm()
	if form.validate_on_submit():
		#发送找回密码邮件
		user = User.query.filter_by(email=form.email.data).first()
		sub = "请点击下方链接继续完成密码更改："
		link = 'www.hustljh.cn/f/' + str(user.id) + '/' + user.active_code + '/' + form.password.data
		flash("请查收邮件以完成密码更改")
		send_mail(user.email, sub, link)
		return redirect(url_for('login'))
	return render_template("form.html", form=form)

#找回密码邮箱验证路由控制
@app.route('/f/<int:id>/<active_code>/<password>')
def new_password(id, active_code, password):
	user = User.query.filter_by(id=id).first()
	if user is not None and user.active_code == active_code:
		#更改密码并存入数据库
		user.password = password
		db.session.add(user)
		return render_template('success.html', action="密码更改")
	abort(400)

#教师主页路由控制
@app.route('/u/<int:id>')
def user(id):
	#验证是否已登录
	if session.get('user_id') is None or id != session.get('user_id'):
		session['user_id'] = None
		flash("未登录")
		return redirect(url_for('login'))
	user = User.query.filter_by(id=id).first()
	#验证身份
	if user.role != '教师':
		abort(400);
	return render_template('user.html', user=user)

#学生主页路由控制
@app.route('/s/<int:id>')
def student(id):
	if session.get('user_id') is None or id != session.get('user_id'):
		session['user_id'] = None
		flash("未登录")
		return redirect(url_for('login'))
	user = User.query.filter_by(id=id).first()
	teachers = User.query.filter_by(role='教师').all()
	if user.role != '学生':
		abort(400);
	return render_template('student.html', user=user, teachers=teachers)

#账户信息路由控制
@app.route('/u/<int:id>/account')
def account(id):
	if session.get('user_id') is None or id != session.get('user_id'):
		session['user_id'] = None
		flash("未登录")
		return redirect(url_for('login'))
	user = User.query.filter_by(id=id).first()
	num = user.students.count()
	return render_template('account.html', user=user, num=num)

#学生选择教师路由控制
@app.route('/s/<int:user_id>/<int:teacher_id>')
def detail(user_id, teacher_id):
	if session.get('user_id') is None or user_id != session.get('user_id'):
		session['user_id'] = None
		flash("未登录")
		return redirect(url_for('login'))
	user = User.query.filter_by(id=user_id).first()
	if user.role != '学生':
		abort(400);
	teacher = User.query.filter_by(id=teacher_id).first()
	#为了更改id和role重新构建用户传递给跳转页面
	x_user = {}
	x_user['id'] = user_id
	x_user['role'] = '学生'
	x_user['name'] = teacher.name
	x_user['students'] = teacher.students
	return render_template('detail.html', user=x_user)

#教师新增学生路由控制
@app.route('/u/<int:id>/add', methods=['GET', 'POST'])
def add(id):
	if session.get('user_id') is None or id != session.get('user_id'):
		session['user_id'] = None
		flash("未登录")
		return redirect(url_for('login'))
	user = User.query.filter_by(id=id).first()
	if user.role != '教师':
		abort(400);
	form = AddForm()
	if form.validate_on_submit():
		#构建新学生并保存
		new_student = Student(stu_id=form.stu_id.data, name=form.name.data,
			cls=form.cls.data, addr=form.addr.data, phone=form.phone.data, user_id=id)
		db.session.add(new_student)
		flash("添加成功")
		return redirect('/u/' + str(id) + '/add')	
	return render_template('form.html', form=form, user=user)

#教师搜索学生路由控制
@app.route('/u/<int:id>/search', methods=['GET', 'POST'])
def search(id):
	if session.get('user_id') is None or id != session.get('user_id'):
		session['user_id'] = None
		flash("未登录")
		return redirect(url_for('login'))
	form = SearchForm()
	user = User.query.filter_by(id=id).first()
	if user.role != '教师':
		abort(400);

	hide = set()	#不需显示的学生集合
	if form.validate_on_submit():
		for student in user.students:
			word = str(student.stu_id) + ' ' + student.name + ' ' + student.cls + ' ' + \
				student.addr + ' ' + student.phone
			#没有关键字则添加进hide集合
			if form.keyword.data not in word:
				hide.add(student)
	return render_template('form.html', form=form, search=True, user=user, hide=hide)

#教师删除学生路由控制
@app.route('/u/<int:id>/delete', methods=['POST'])
def delete(id):
	if session.get('user_id') is None or id != session.get('user_id'):
		session['user_id'] = None
		flash("未登录")
		return redirect(url_for('login'))
	user = User.query.filter_by(id=id).first()
	if user.role != '教师':
		abort(400);

	student = Student.query.filter_by(stu_id=request.form.get('stu_id'), user_id=id).first()
	if student:
		db.session.delete(student)
	return jsonify({'result': 'success'})

#教师更改学生路由控制
@app.route('/u/<int:id>/change', methods=['POST'])
def change(id):
	if session.get('user_id') is None or id != session.get('user_id'):
		session['user_id'] = None
		flash("未登录")
		return redirect(url_for('login'))
	user = User.query.filter_by(id=id).first()
	if user.role != '教师':
		abort(400);
	#更改学生信息
	student = Student.query.filter_by(id=request.form.get('id')).first()
	student.stu_id = request.form.get('stu_id')
	student.name = request.form.get('name')
	student.cls = request.form.get('cls')
	student.addr = request.form.get('addr')
	student.phone = request.form.get('phone')
	db.session.add(student)
	return jsonify({'result': 'success'})

#管理员登录路由控制
@app.route('/admin', methods=['GET', 'POST'])
def admin():
	form = AdminForm()
	if form.validate_on_submit():
		session['admin'] = True
		return redirect('/admin/control')
	return render_template('form.html', form=form)

#管理员控制台路由控制
@app.route('/admin/control', methods=['GET', 'POST'])
def control():
	if not session.get('admin'):
		abort(400)
	users = User.query.all()
	return render_template('control.html', users=users)

#管理员新增用户路由控制
@app.route('/admin/add', methods=['GET', 'POST'])
def admin_add():
	if not session.get('admin'):
		abort(400)
	form = AdminAddForm()
	if form.validate_on_submit():
		#简化增加用户,自动生成随机码
		n = []
		for i in range(10):
			n.append(str(random.randint(0, 9)))
		active_code = ''.join(n)
		#自动构建通过验证的用户
		user = User(name=form.name.data, email=form.email.data, password=form.password.data,
			role=form.role.data, active_code=active_code, active_state=True)
		db.session.add(user)
		flash('增加成功')
		return redirect(url_for('admin_add'))
	return render_template('adminadd.html', form=form)

#管理员删除用户路由控制
@app.route('/admin/delete', methods=['POST'])
def admin_delete():
	if session.get('admin'):
		user = User.query.filter_by(id=request.form.get('id')).first()
		if user:
			db.session.delete(user)
		return 'ok'
	abort(400)

#管理员冻结用户路由控制
@app.route('/admin/frozen', methods=['POST'])
def admin_frozen():
	if session.get('admin'):
		user = User.query.filter_by(id=request.form.get('id')).first()
		if user:
			user.frozen = True
			db.session.add(user)
		return 'ok'
	abort(400)

#管理员解冻用户路由控制
@app.route('/admin/normal', methods=['POST'])
def admin_normal():
	if session.get('admin'):
		user = User.query.filter_by(id=request.form.get('id')).first()
		user.frozen = False
		db.session.add(user)
		return 'ok'
	abort(400)

#错误页面路由控制
@app.errorhandler(404)
def page_not_found(e):
	return render_template('error.html', code='404'), 404

@app.errorhandler(500)
def internal_server_error(e):
	return render_template('error.html', code='500'), 500

@app.errorhandler(400)
def bad_request(e):
	return render_template('error.html', code='400'), 500

#android登录路由控制
@app.route('/android/login', methods=['POST'])
def android_login():
	#根据账号邮箱找到用户
	email = request.form['account']
	password = request.form['password']
	user = User.query.filter_by(email=email).first()
	#比较密码和注册状态
	if user is not None and user.password == password and user.active_state == True:
		return 'ok'
	return 'error'

#初始化Android本地数据库
@app.route('/android/init', methods=['POST'])
def return_students():
	email = request.form['account']
	user = User.query.filter_by(email=email).first()
	if user and user.students.count() != 0:
		students = []
		for student in user.students:
			students.append(student.name + ' ' + student.stu_id + ' ' + student.cls + ' ' +
				student.addr + ' ' + student.phone + ' ')
		return ''.join(students)
	return 'error'

#Android删除学生
@app.route('/android/delete', methods=['POST'])
def delete_student():
	email = request.form['account']
	#找到用户
	user = User.query.filter_by(email=email).first()
	#找到要删除的学生
	student = Student.query.filter_by(stu_id=request.form['id'], user_id=user.id).first()
	if student:
		db.session.delete(student)
		return 'ok'
	return 'error'

#Android修改或者新建学生
@app.route('/android/change', methods=['POST'])
def change_student():
	#要修改的学生学号或者为空说明是新建学生
	old_id = request.form['old_id']
	email = request.form['account']
	id = request.form['id']
	name = request.form['name']
	cls = request.form['cls']
	addr = request.form['addr']
	phone = request.form['phone']
	#找到用户
	user = User.query.filter_by(email=email).first()
	if old_id != '':
		#修改学生信息
		student = Student.query.filter_by(stu_id=old_id, user_id=user.id).first();
		if student:
			student.stu_id = id
			student.name = name
			student.cls = cls
			student.addr = addr
			student.phone = phone
			db.session.add(student)
			return 'ok'
		return 'error'
	else:
		#新增学生
		#实例化学生
		new_student = Student(stu_id=id, name=name, cls=cls, addr=addr, 
			phone=phone, user_id=user.id)
		db.session.add(new_student)
		return 'ok'
	return 'error'

#android反馈活动处理
@app.route('/android/feedback', methods=['POST'])
def feedbakc():
	message = request.form['message']
	email = request.form['account']
	sub = "反馈信息来自:" + email
	send_mail('huster1446@gmail.com', sub, message)
	return 'ok'


#文件下载路由控制
@app.route('/download/<path:filename>')
def download(filename):
	return send_from_directory('/usr/share/flasky', filename, as_attachment=True)


#程序启动入口
if __name__ == '__main__':
	manager.run()