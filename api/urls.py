
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('nileuser/', admin.site.urls),
    path('api/', include('userapps.urls'))
]
