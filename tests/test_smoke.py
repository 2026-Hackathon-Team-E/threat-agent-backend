"""스캐폴드 확인용 스모크 테스트. 패키지가 import 되는지만 본다. 담당: D redsun2."""


def test_package_imports():
    import app  # noqa: F401
