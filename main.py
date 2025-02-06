import json
import os
import functools
from astrbot.api.all import *
from astrbot.api.event import PermissionType  # 使用框架内置的权限枚举

# 默认数据文件路径
DEFAULT_DATA_FILE = "permissions.json"

class PermissionManager:
    """
    持久化权限管理系统：
      - roles: 角色定义，格式为 {role_name: {"level": int, "description": str}}
      - user_roles: 用户角色映射，格式为 {user_id: role_name}
      - command_permissions: 指令权限要求，格式为 {command_name: required_level}
    """
    def __init__(self, data_file: str = DEFAULT_DATA_FILE, enable_log: bool = True):
        self.data_file = data_file
        self.enable_log = enable_log
        self.data = {"roles": {}, "user_roles": {}, "command_permissions": {}}
        self.load()
    
    def _log(self, msg: str):
        if self.enable_log:
            print("[PermissionManager]", msg)
    
    def load(self):
        """加载持久化数据；如果文件不存在，则写入默认数据。"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, "r", encoding="utf8") as f:
                    self.data = json.load(f)
                self._log(f"加载权限数据成功：{self.data_file}")
            except Exception as e:
                self._log(f"加载权限数据失败: {e}")
                self.data = {"roles": {}, "user_roles": {}, "command_permissions": {}}
        else:
            self._log("权限数据文件不存在，初始化默认数据")
            # 默认角色：default（普通用户，级别 0）和 admin（管理员，级别 50）
            self.data["roles"]["default"] = {
                "level": 0,
                "description": "普通用户默认角色"
            }
            self.data["roles"]["admin"] = {
                "level": 50,
                "description": "管理员角色"
            }
            # 默认指令权限要求（数值越高表示要求越高）
            self.data["command_permissions"]["create_role"] = 50
            self.data["command_permissions"]["set_role"] = 50
            self.data["command_permissions"]["set_cmd_perm"] = 50
            # 普通指令默认要求为 0
            self.data["command_permissions"]["helloworld"] = 0
            self.data["command_permissions"]["my_level"] = 0
            self.data["command_permissions"]["list_roles"] = 0
            self.data["command_permissions"]["list_cmd_perm"] = 0
            self.save()
    
    def save(self):
        """保存当前权限数据到文件。"""
        try:
            with open(self.data_file, "w", encoding="utf8") as f:
                json.dump(self.data, f, indent=4)
            self._log(f"权限数据保存成功：{self.data_file}")
        except Exception as e:
            self._log(f"保存权限数据失败: {e}")
    
    def get_user_level(self, user_id: str) -> int:
        """
        根据用户 ID 返回其权限等级；
        若用户未被分配角色，则默认为 default 角色（等级 0）。
        """
        role = self.data["user_roles"].get(user_id, "default")
        level = self.data["roles"].get(role, {"level": 0})["level"]
        self._log(f"查询用户 {user_id} 的角色 '{role}'，等级 {level}")
        return level
    
    def set_user_role(self, user_id: str, role_name: str) -> bool:
        """为指定用户设置角色，返回 True 表示成功；角色不存在返回 False。"""
        if role_name in self.data["roles"]:
            self.data["user_roles"][user_id] = role_name
            self.save()
            self._log(f"用户 {user_id} 设置为角色 '{role_name}'")
            return True
        self._log(f"设置角色失败：角色 '{role_name}' 不存在")
        return False
    
    def create_role(self, role_name: str, level: int, description: str) -> bool:
        """创建新角色；若角色已存在则返回 False。"""
        if role_name in self.data["roles"]:
            self._log(f"角色创建失败：角色 '{role_name}' 已存在")
            return False
        self.data["roles"][role_name] = {"level": level, "description": description}
        self.save()
        self._log(f"角色 '{role_name}' 创建成功，级别 {level}")
        return True
    
    def set_command_permission(self, command_name: str, required_level: int):
        """设置指定指令的最低权限要求。"""
        self.data["command_permissions"][command_name] = required_level
        self.save()
        self._log(f"指令 '{command_name}' 权限要求更新为 {required_level} 级")
    
    def get_command_permission(self, command_name: str) -> int:
        """获取指定指令的最低权限要求；若未设置，则默认为 0。"""
        level = self.data["command_permissions"].get(command_name, 0)
        self._log(f"指令 '{command_name}' 的权限要求为 {level} 级")
        return level

def dynamic_permission_required(command_name):
    """
    动态权限检查装饰器：
      - 如果传入的函数已经由内置的 @permission_type(PermissionType.ADMIN) 修饰，
        则直接调用，不做持久化权限检查。
      - 否则要求调用者的持久化角色等级大于或等于该命令设置的最低权限要求。
    """
    def decorator(func):
        # 检查是否已经被内置 ADMIN 修饰（假设内置修饰器设置了 __permission_type__ 属性）
        if getattr(func, "__permission_type__", None) == PermissionType.ADMIN:
            @functools.wraps(func)
            async def wrapper(self, event: AstrMessageEvent, *args, **kwargs):
                async for message in func(self, event, *args, **kwargs):
                    yield message
            return wrapper
        else:
            @functools.wraps(func)
            async def wrapper(self, event: AstrMessageEvent, *args, **kwargs):
                user_level = self.permission_manager.get_user_level(event.get_sender_id())
                required_level = self.permission_manager.get_command_permission(command_name)
                if user_level >= required_level:
                    async for message in func(self, event, *args, **kwargs):
                        yield message
                else:
                    yield event.plain_result(
                        f"抱歉，权限不足。指令 '{command_name}' 需要权限 {required_level} 级，而你只有 {user_level} 级。"
                    )
                    event.stop_event()
            return wrapper
    return decorator

@register("permission_plugin", "Your Name", 
          "分级权限管理系统插件（支持持久化、角色管理；运行命令时满足“角色大于命令设置”或命令修饰为@permission_type(PermissionType.ADMIN)均可）", 
          "1.0.0", "repo url")
class MyPlugin(Star):
    def __init__(self, context: Context, config: dict = None):
        """
        初始化插件，同时加载配置：
          - config: 插件配置字典，由 _conf_schema.json 生成，包含 enable_log、data_file 等配置项
        """
        super().__init__(context)
        data_file = config.get("data_file", DEFAULT_DATA_FILE) if config else DEFAULT_DATA_FILE
        enable_log = config.get("enable_log", True) if config else True
        self.permission_manager = PermissionManager(data_file=data_file, enable_log=enable_log)
    
    # 普通指令：只使用动态权限检查，依赖持久化角色数据
    @command("helloworld")
    @dynamic_permission_required("helloworld")
    async def helloworld(self, event: AstrMessageEvent):
        '''hello world 指令示例。'''
        user_name = event.get_sender_name()
        yield event.plain_result(f"Hello, {user_name}!")
    
    # 管理员专用指令：要求调用者使用内置的 ADMIN 修饰器，通过内置权限判断，
    # 同时动态检查装饰器会检测到 __permission_type__ 为 ADMIN，从而绕过持久化权限检查
    @command("create_role")
    @dynamic_permission_required("create_role")
    @permission_type(PermissionType.ADMIN)
    async def create_role(self, event: AstrMessageEvent, role_name: str, level: int, *, description: str = ""):
        '''
        创建新角色命令，仅允许内置 ADMIN 用户调用。
        
        Args:
            role_name(string): 角色名称
            level(number): 角色级别（数值越大权限越高）
            description(string): 角色描述（可选）
        '''
        if self.permission_manager.create_role(role_name, level, description):
            yield event.plain_result(f"角色 '{role_name}' 创建成功，级别为 {level}。")
        else:
            yield event.plain_result(f"角色 '{role_name}' 已存在！")
    
    @command("set_role")
    @dynamic_permission_required("set_role")
    @permission_type(PermissionType.ADMIN)
    async def set_role(self, event: AstrMessageEvent, user_id: str, role_name: str):
        '''
        为指定用户设置角色命令，仅允许内置 ADMIN 用户调用。
        
        Args:
            user_id(string): 用户 ID
            role_name(string): 角色名称
        '''
        caller = event.get_sender_id()
        caller_level = self.permission_manager.get_user_level(caller)
        # 检查目标用户当前权限级别；若目标权限高于或等于调用者，则不允许修改（除非是自己设置）
        target_role = self.permission_manager.data["user_roles"].get(user_id, "default")
        target_level = self.permission_manager.data["roles"].get(target_role, {"level": 0})["level"]
        if caller != user_id and caller_level <= target_level:
            yield event.plain_result("不能为权限高于或等于你级别的用户设置角色！")
            return
        
        if self.permission_manager.set_user_role(user_id, role_name):
            yield event.plain_result(f"用户 {user_id} 的角色已设置为 '{role_name}'。")
        else:
            yield event.plain_result(f"角色 '{role_name}' 不存在！")
    
    @command("set_cmd_perm")
    @dynamic_permission_required("set_cmd_perm")
    @permission_type(PermissionType.ADMIN)
    async def set_cmd_perm(self, event: AstrMessageEvent, command_name: str, required_level: int):
        '''
        设置指定指令最低权限要求命令，仅允许内置 ADMIN 用户调用。
        
        Args:
            command_name(string): 指令名称
            required_level(number): 所需最低权限级别
        '''
        self.permission_manager.set_command_permission(command_name, required_level)
        yield event.plain_result(f"指令 '{command_name}' 的权限要求已设置为 {required_level} 级。")
    
    # 查询自己当前权限等级（普通用户）
    @command("my_level")
    @dynamic_permission_required("my_level")
    async def my_level(self, event: AstrMessageEvent):
        '''查询自己当前权限等级的命令。'''
        user_level = self.permission_manager.get_user_level(event.get_sender_id())
        yield event.plain_result(f"你的权限等级是 {user_level}。")
    
    @command("list_roles")
    @dynamic_permission_required("list_roles")
    async def list_roles(self, event: AstrMessageEvent):
        '''列出所有角色及其权限信息的命令。'''
        roles = self.permission_manager.data["roles"]
        lines = ["角色列表:"]
        for role, info in roles.items():
            lines.append(f"{role}: 等级 {info['level']} - {info.get('description', '')}")
        yield event.plain_result("\n".join(lines))
    
    @command("list_cmd_perm")
    @dynamic_permission_required("list_cmd_perm")
    async def list_cmd_perm(self, event: AstrMessageEvent):
        '''列出所有指令权限要求的命令。'''
        cmd_perms = self.permission_manager.data["command_permissions"]
        lines = ["指令权限设置:"]
        for cmd, level in cmd_perms.items():
            lines.append(f"{cmd}: 需要 {level} 级")
        yield event.plain_result("\n".join(lines))
