   M S B A M L   `   `   `  ����A  =Client, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null!clr-namespace:WpfApp1WpfApp1  5   	   clr-namespace:ClientClient  6-       WpfApp1.MainWindow   5   	   W SPresentationCore, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089R NWindowsBase, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     5   	   R NSystem.Xaml, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   'localclr-namespace:WpfApp1     5   	   'clientclr-namespace:Client     6-     � Title$  
MainWindow��5   	   $	��449��6   $	��800��6)    � DataContext 5
        WpfApp1.MainViewModel  5   
   .��5      �  � ColumnDefinitions 5   
   �� 5      $	��200 �6   �� 5      .+�5   
   ]� .+�5      �� $��25��6   $	��Top=�6"   ��67   �� *
Username+ �� UpdateSourceTrigger$ PropertyChanged=��� 5      $��25��6   $	��Top=�6!   $��Connect��66   ��6H   �� *ConnectToServerCommand+�� 5      ��6   �� *_users+��5      �� 5      .R�5      �� ��6$   �� *
Username+5      5      5      �� 5   
   $��1��6   .+�5      �� $	��380��6   ��6$   �� *
Messages+�� 5        �� Orientation$ 
Horizontal=�6   .+�5!      �� $��55��6   $	��541��6&   $��Center=�62   ��6M   �� *	Message+$ PropertyChanged=��� 5"      $��55��6   $
��Send��6$   ��63   �� *SendMessageCommand+$ PropertyChanged=�5#      5$      5%      5&      