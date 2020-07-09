from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status as ccokt

# 公钥私钥
from drf_bzedu.libs.geetest import GeetestLib
from user.utils import fun

pc_geetest_id = "6f91b3d2afe94ed29da03c14988fb4ef"
pc_geetest_key = "7a01b1933685931ef5eaf5dabefd3df2"


# 获取极验验证码并验证
class Captcha(APIView):
    user_id = 0
    status = False

    # 获取验证码
    def get(self, request, *args, **kwargs):
        username = request.query_params.get('username')
        user = fun(username)
        if user is None:
            return Response({"message": "用户不存在"}, status=ccokt.HTTP_400_BAD_REQUEST)
        self.user_id = user.id

        gt = GeetestLib(pc_geetest_id, pc_geetest_key)
        self.status = gt.pre_process(self.user_id)
        response_str = gt.get_response_str()
        return Response(response_str)

    # 验证验证码
    def post(self, request, *args, **kwargs):
        gt = GeetestLib(pc_geetest_id, pc_geetest_key)
        challenge = request.POST.get(gt.FN_CHALLENGE, '')
        validate = request.POST.get(gt.FN_VALIDATE, '')
        seccode = request.POST.get(gt.FN_SECCODE, '')
        # 判断用户是否存在
        if self.user_id:
            result = gt.success_validate(challenge, validate, seccode, self.user_id)
        else:
            result = gt.failback_validate(challenge, validate, seccode)
        result = {"status": "成功"} if result else {"status": "失败"}
        return Response(result)
