
import tkinter as tk
from tkinter import ttk  
from scapy.all import * 
from scapy.layers.inet import IP, TCP, UDP, ICMP 
import netifaces as ni 
import winreg as wr 
from scapy.layers.l2 import getmacbyip, Ether 

class PacketGeneratorApp(tk.Tk):
    def __init__(self):
        super().__init__()  # Инициализация главного окна

        # Переменные для хранения пакетов
        self.num_packets = 0  # Счетчик пакетов
        self.packet_queue = []  # Очередь пакетов для отправки

        # Настройка главного окна
        self.title("Packet Generator")  # Заголовок окна
        self.geometry("1000x600")  # Размер окна
        self.resizable(False, False)  # Запрет изменения размера
        self.attributes('-alpha', 0.85)  # Прозрачность окна (85%)

        # Главный контейнер
        self.protocol_frame = tk.Frame(self)  # Фрейм для всего содержимого
        self.protocol_frame.pack(pady=5, padx=5, fill="both", expand=True)

        # Фрейм выбора протокола
        self.choice_frame = tk.Frame(self.protocol_frame)
        self.choice_frame.pack()

        # Выбор протокола
        self.protocol_label = tk.Label(self.choice_frame, text="Протокол:", font=("Arial", 14))
        self.protocol_label.pack(side="left", pady=1, padx=5)

        self.protocol_var = tk.StringVar(value="TCP")  # Переменная для хранения выбранного протокола
        self.protocol_combobox = ttk.Combobox(self.choice_frame, values=["TCP", "UDP", "ICMP", "IP"], textvariable=self.protocol_var, state="readonly")
        self.protocol_combobox.bind("<<ComboboxSelected>>", self.update_packet_fields)  # Обработчик смены протокола
        self.protocol_combobox.pack(side="left", pady=1)

        # Фрейм для всех параметров пакета
        self.packet_frame = tk.Frame(self.protocol_frame)
        self.packet_frame.pack(pady=5, padx=5, fill="both", expand=True)

        # Левая панель управления
        self.buttom_frame = tk.Frame(self.packet_frame)
        self.buttom_frame.pack(side="left", pady=1, padx=5)

        # Получение списка сетевых интерфейсов
        self.interfaces_all = ni.interfaces()  # Получить все GUID интерфейсов
        self.x = self.get_connection_name_from_guid(self.interfaces_all)  # Преобразовать GUID в читаемые имена

        # Выбор сетевого интерфейса
        self.int_label = tk.Label(self.buttom_frame, text="Интерфейс:", font=("Arial", 14))
        self.int_label.pack(pady=1, padx=5)

        self.int_var = tk.StringVar(value="Беспроводная сеть")  # Интерфейс по умолчанию
        self.int_combobox = ttk.Combobox(self.buttom_frame, values=self.x, textvariable=self.int_var, state="readonly")
        self.int_combobox.pack(pady=1, fill="x")

        # Кнопка генерации пакета
        self.generate_button = tk.Button(self.buttom_frame, text="Сгенерировать пакет", command=self.generate_packet)
        self.generate_button.pack(fill="x", pady=10)

        # Кнопка отправки пакетов
        self.generate_button = tk.Button(self.buttom_frame, text="Отправить пакеты", command=self.send_packet)
        self.generate_button.pack(fill="x", pady=10)

        # Информация о количестве пакетов в очереди
        self.info_packet_label = tk.Label(self.buttom_frame, text="Пакетов в очереди:", font=("Arial", 12))
        self.info_packet_label.pack(pady=1)

        self.info_packet = tk.Label(self.buttom_frame, text=str(self.num_packets), font=("Arial", 12))
        self.info_packet.pack(pady=1)

        # Кнопка удаления последнего пакета
        self.generate_button = tk.Button(self.buttom_frame, text="Удалить последний пакет", command=self.del_packet)
        self.generate_button.pack(fill="x", pady=10)

        # Кнопка очистки очереди
        self.generate_button = tk.Button(self.buttom_frame, text="Удалить все пакеты", command=self.del_all_packet)
        self.generate_button.pack(fill="x", pady=10)

        # ==================== IP ПАРАМЕТРЫ ====================
        self.ip_frame = tk.Frame(self.packet_frame)
        self.ip_frame.pack(side="left", pady=10, padx=10, fill="both", expand=True)

        self.ip_label = tk.Label(self.ip_frame, text="IP:", font=("Arial", 12))
        self.ip_label.pack(pady=5)

        self.ip_block = tk.Frame(self.ip_frame)
        self.ip_block.pack(side="top", fill="x", padx=[5, 5], pady=5)

        # IP-адреса
        self.ip_address = tk.Frame(self.ip_block)
        self.ip_address.pack(side="left", padx=5, pady=5)

        self.ip_address_label = tk.Label(self.ip_address, text="IP-адресa:", font=("Arial", 12))
        self.ip_address_label.pack(anchor="nw", padx=5)

        # IP источника
        self.ip_src = tk.Frame(self.ip_address)
        self.ip_src.pack(fill="x", padx=[5, 5])
        self.ip_source_label = tk.Label(self.ip_src, text="Источник:")
        self.ip_source_label.pack(side="left", ipadx=1)
        self.ip_source_entry = tk.Entry(self.ip_src, width=20)  # Поле ввода IP-адреса источника
        self.ip_source_entry.insert(0, "192.168.43.65")  # Значение по умолчанию
        self.ip_source_entry.pack(side="right")
         
        # IP назначения
        self.ip_dst = tk.Frame(self.ip_address)
        self.ip_dst.pack(fill="x", padx=[5, 5], pady=[5,5])
        self.ip_destination_label = tk.Label(self.ip_dst, text="Назначение:")
        self.ip_destination_label.pack(side="left")
        self.ip_destination_entry = tk.Entry(self.ip_dst, width=20)  # Поле ввода IP-адреса назначения
        self.ip_destination_entry.insert(0, "8.8.8.8")  # Google DNS по умолчанию
        self.ip_destination_entry.pack(side="right")  

        # Параметры IP-заголовка
        self.ip_params = tk.Frame(self.ip_frame)
        self.ip_params.pack(fill="x", padx=[5, 5], side="bottom", pady=5)

        self.ip_params_label = tk.Label(self.ip_params, text="Параметры пакеты:", font=("Arial", 12))
        self.ip_params_label.pack(anchor="nw", padx=5)

        # IHL (Internet Header Length) - длина заголовка
        self.ihl = tk.Frame(self.ip_params)
        self.ihl.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.ihl_label = tk.Label(self.ihl, text="Длина заголовка:", font=("Arial", 12))
        self.ihl_label.pack(side="left")

        self.ihl_var = tk.StringVar(value="5")  # 5 = 20 байт (минимум)
        self.ihl_combobox = ttk.Combobox(self.ihl, values=["5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15"], textvariable=self.ihl_var, state="readonly", width=10)
        self.ihl_combobox.pack(side="right", padx=[5, 0])

        # TOS (Type of Service) - тип обслуживания
        self.tos = tk.Frame(self.ip_params)
        self.tos.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.tos_label = tk.Label(self.tos, text="Тип обслуживания:", font=("Arial", 12))
        self.tos_label.pack(side="left")

        self.tos_entry = tk.Entry(self.tos, width=10)
        self.tos_entry.insert(0, 0)  # 0 = обычная приоритетность
        self.tos_entry.pack(side="right") 

        # Total Length - общая длина пакета
        self.total_len = tk.Frame(self.ip_params)
        self.total_len.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.total_len_label = tk.Label(self.total_len, text="Общая длина:", font=("Arial", 12))
        self.total_len_label.pack(side="left")

        self.total_len_entry = tk.Entry(self.total_len, width=10)
        self.total_len_entry.insert(0, 32)  # Минимальный размер пакета
        self.total_len_entry.pack(side="right")

        # ID - идентификатор пакета
        self.id = tk.Frame(self.ip_params)
        self.id.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.id_label = tk.Label(self.id, text="Идентификатор:", font=("Arial", 12))
        self.id_label.pack(side="left")

        self.id_entry = tk.Entry(self.id, width=10)
        self.id_entry.insert(0, 12345)  # Уникальный ID пакета
        self.id_entry.pack(side="right")

        # Fragment Offset - смещение фрагмента
        self.fragment_offset = tk.Frame(self.ip_params)
        self.fragment_offset.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.fragment_offset_label = tk.Label(self.fragment_offset, text="Смещение:", font=("Arial", 12))
        self.fragment_offset_label.pack(side="left")

        self.fragment_offset_entry = tk.Entry(self.fragment_offset, width=10)
        self.fragment_offset_entry.insert(0, 0)  # 0 = нет фрагментации
        self.fragment_offset_entry.pack(side="right")

        # TTL (Time To Live) - время жизни
        self.TTL = tk.Frame(self.ip_params)
        self.TTL.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.TTL_label = tk.Label(self.TTL, text="Время жизни:", font=("Arial", 12))
        self.TTL_label.pack(side="left")

        self.TTL_entry = tk.Entry(self.TTL, width=10)
        self.TTL_entry.insert(0, 128)  # Стандартное значение для Windows
        self.TTL_entry.pack(side="right")

        # Checksum - контрольная сумма IP-заголовка
        self.check_sum = tk.Frame(self.ip_params)
        self.check_sum.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.check_sum_label = tk.Label(self.check_sum, text="Контрольная сумма:", font=("Arial", 12))
        self.check_sum_label.pack(side="left")

        self.check_sum_entry = tk.Entry(self.check_sum, width=10)
        self.check_sum_entry.insert(0, 0)  # 0 = автоматический расчет
        self.check_sum_entry.pack(side="right")

        # ==================== TCP ПАРАМЕТРЫ ====================
        self.tcp_frame = tk.Frame(self.packet_frame)
        self.tcp_frame.pack(side="left", pady=10, padx=10, fill="both", expand=True)

        self.tcp_label = tk.Label(self.tcp_frame, text="TCP:", font=("Arial", 12))
        self.tcp_label.pack(pady=5)

        # TCP Source Port
        self.tcp_src = tk.Frame(self.tcp_frame)
        self.tcp_src.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.tcp_source_port_label = tk.Label(self.tcp_src, text="Источник Port:")
        self.tcp_source_port_label.pack(side="left", padx=5)

        self.tcp_source_port_entry = tk.Entry(self.tcp_src, width=15)
        self.tcp_source_port_entry.insert(0, 9000)  # Порт источника
        self.tcp_source_port_entry.pack(side="right", padx=5)

        # TCP Destination Port
        self.tcp_dst = tk.Frame(self.tcp_frame)
        self.tcp_dst.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.tcp_destination_port_label = tk.Label(self.tcp_dst, text="Назначение Port:")
        self.tcp_destination_port_label.pack(side="left", padx=5)

        self.tcp_destination_port_entry = tk.Entry(self.tcp_dst, width=15)
        self.tcp_destination_port_entry.insert(0, 80)  # HTTP порт
        self.tcp_destination_port_entry.pack(side="right", padx=5)

        # TCP Sequence Number
        self.tcp_seq_num = tk.Frame(self.tcp_frame)
        self.tcp_seq_num.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.tcp_seq_num_label = tk.Label(self.tcp_seq_num, text="Sequence Number:")
        self.tcp_seq_num_label.pack(side="left", padx=5)

        self.tcp_seq_num_entry = tk.Entry(self.tcp_seq_num, width=15)
        self.tcp_seq_num_entry.insert(0, 1)  # Начальный номер последовательности
        self.tcp_seq_num_entry.pack(side="right", padx=5)

        # TCP Acknowledgement Number
        self.tcp_ack_num = tk.Frame(self.tcp_frame)
        self.tcp_ack_num.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.tcp_ack_num_label = tk.Label(self.tcp_ack_num, text="Acknowledgement Number:")
        self.tcp_ack_num_label.pack(side="left", padx=5)

        self.tcp_ack_num_entry = tk.Entry(self.tcp_ack_num, width=15)
        self.tcp_ack_num_entry.insert(0, 1)  # Номер подтверждения
        self.tcp_ack_num_entry.pack(side="right", padx=5)

        # TCP Data Offset
        self.tcp_data_offset = tk.Frame(self.tcp_frame)
        self.tcp_data_offset.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.tcp_data_offset_label = tk.Label(self.tcp_data_offset, text="Data Offset:")
        self.tcp_data_offset_label.pack(side="left", padx=5)

        self.tcp_data_offset_entry = tk.Entry(self.tcp_data_offset, width=15)
        self.tcp_data_offset_entry.insert(0, 5)  # 5 = 20 байт (минимальный заголовок TCP)
        self.tcp_data_offset_entry.pack(side="right", padx=5)

        # TCP Reserved
        self.tcp_reserved = tk.Frame(self.tcp_frame)
        self.tcp_reserved.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.tcp_reserved_label = tk.Label(self.tcp_reserved, text="Reserved:")
        self.tcp_reserved_label.pack(side="left", padx=5)

        self.tcp_reserved_entry = tk.Entry(self.tcp_reserved, width=15)
        self.tcp_reserved_entry.insert(0, 0)  # Зарезервированные биты (должны быть 0)
        self.tcp_reserved_entry.pack(side="right", padx=5)

        # TCP Flags
        self.tcp_flags = tk.Frame(self.tcp_frame)
        self.tcp_flags.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.tcp_flags_label = tk.Label(self.tcp_flags, text="Flags:")
        self.tcp_flags_label.pack(side="left", padx=5)

        # URG - Urgent Pointer field significant
        self.check_var_urg = tk.StringVar(value="off")
        self.checkbox_urg = tk.Checkbutton(self.tcp_flags, text="URG", variable=self.check_var_urg, onvalue="on", offvalue="off")
        self.checkbox_urg.pack(pady=5)

        # ACK - Acknowledgement field significant
        self.check_var_ack = tk.StringVar(value="off")
        self.checkbox_ack = tk.Checkbutton(self.tcp_flags, text="ACK", variable=self.check_var_ack, onvalue="on", offvalue="off")
        self.checkbox_ack.pack(pady=5)

        # PSH - Push function
        self.check_var_psh = tk.StringVar(value="off")
        self.checkbox_psh = tk.Checkbutton(self.tcp_flags, text="PSH", variable=self.check_var_psh, onvalue="on", offvalue="off")
        self.checkbox_psh.pack(pady=5)  

        # RST - Reset connection
        self.check_var_rst = tk.StringVar(value="off")
        self.checkbox_rst = tk.Checkbutton(self.tcp_flags, text="RST", variable=self.check_var_rst, onvalue="on", offvalue="off")
        self.checkbox_rst.pack(pady=5)  

        # SYN - Synchronize sequence numbers
        self.check_var_syn = tk.StringVar(value="off")
        self.checkbox_syn = tk.Checkbutton(self.tcp_flags, text="SYN", variable=self.check_var_syn, onvalue="on", offvalue="off")
        self.checkbox_syn.pack(pady=5) 

        # FIN - No more data from sender
        self.check_var_fin = tk.StringVar(value="off")
        self.checkbox_fin = tk.Checkbutton(self.tcp_flags, text="FIN", variable=self.check_var_fin, onvalue="on", offvalue="off")
        self.checkbox_fin.pack(pady=5) 

        # TCP Window Size
        self.tcp_window_size = tk.Frame(self.tcp_frame)
        self.tcp_window_size.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.tcp_window_size_label = tk.Label(self.tcp_window_size, text="Window Size:")
        self.tcp_window_size_label.pack(side="left", padx=5)

        self.tcp_window_size_entry = tk.Entry(self.tcp_window_size, width=15)
        self.tcp_window_size_entry.insert(0, 8192)  # Размер окна приема (в байтах)
        self.tcp_window_size_entry.pack(side="right", padx=5)

        # TCP Checksum
        self.tcp_checksum = tk.Frame(self.tcp_frame)
        self.tcp_checksum.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.tcp_checksum_label = tk.Label(self.tcp_checksum, text="Checksum:")
        self.tcp_checksum_label.pack(side="left", padx=5)

        self.tcp_checksum_entry = tk.Entry(self.tcp_checksum, width=15)
        self.tcp_checksum_entry.insert(0, 0)  # 0 = автоматический расчет
        self.tcp_checksum_entry.pack(side="right", padx=5)

        # TCP Urgent Pointer
        self.tcp_urgent_pointer = tk.Frame(self.tcp_frame)
        self.tcp_urgent_pointer.pack(fill="x", padx=[5, 5], pady=[5, 5])

        self.tcp_urgent_pointer_label = tk.Label(self.tcp_urgent_pointer, text="Urgent Pointer:")
        self.tcp_urgent_pointer_label.pack(side="left", padx=5)

        self.tcp_urgent_pointer_entry = tk.Entry(self.tcp_urgent_pointer, width=15)
        self.tcp_urgent_pointer_entry.insert(0, 0)  # Указатель на срочные данные
        self.tcp_urgent_pointer_entry.pack(side="right", padx=5)

        # ==================== UDP ПАРАМЕТРЫ ====================
        self.udp_frame = tk.Frame(self.packet_frame)
        self.udp_frame.pack(side="left", pady=10, padx=10, fill="both", expand=True)

        self.udp_label = tk.Label(self.udp_frame, text="UDP:", font=("Arial", 12))
        self.udp_label.pack(pady=5)

        # UDP Source Port
        self.udp_src = tk.Frame(self.udp_frame)
        self.udp_src.pack(pady=5, padx=5, fill="x")
        
        self.udp_source_port_label = tk.Label(self.udp_src, text="Источник Port:")
        self.udp_source_port_label.pack(side="left", padx=[5, 20])

        self.udp_source_port_entry = tk.Entry(self.udp_src, width=15)
        self.udp_source_port_entry.insert(0, 9000)  # Порт источника
        self.udp_source_port_entry.pack(side="right", padx=5)

        # UDP Destination Port
        self.udp_dst = tk.Frame(self.udp_frame)
        self.udp_dst.pack(pady=5, padx=5, fill="x")

        self.udp_destination_port_label = tk.Label(self.udp_dst, text="Назначение Port:")
        self.udp_destination_port_label.pack(side="left", padx=[5, 20])

        self.udp_destination_port_entry = tk.Entry(self.udp_dst, width=15)
        self.udp_destination_port_entry.insert(0, 9000)  # Порт назначения
        self.udp_destination_port_entry.pack(side="right", padx=5)

        # UDP Length
        self.udp_len = tk.Frame(self.udp_frame)
        self.udp_len.pack(pady=5, padx=5, fill="x")

        self.udp_length_label = tk.Label(self.udp_len, text="Длина:")
        self.udp_length_label.pack(side="left", padx=[5, 20])

        self.udp_length_entry = tk.Entry(self.udp_len, width=15)
        self.udp_length_entry.insert(0, 8)  # Минимальная длина UDP (8 байт)
        self.udp_length_entry.pack(side="right", padx=5)

        # UDP Checksum
        self.udp_checksum = tk.Frame(self.udp_frame)
        self.udp_checksum.pack(pady=5, padx=5, fill="x")

        self.udp_checksum_label = tk.Label(self.udp_checksum, text="Контрольная сумма:")
        self.udp_checksum_label.pack(side="left", padx=[5, 20])

        self.udp_checksum_entry = tk.Entry(self.udp_checksum, width=15)
        self.udp_checksum_entry.insert(0, 0)  # 0 = автоматический расчет
        self.udp_checksum_entry.pack(side="right", padx=5)

        # ==================== ICMP ПАРАМЕТРЫ ====================
        self.icmp_frame = tk.Frame(self.packet_frame)
        self.icmp_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.icmp_label = tk.Label(self.icmp_frame, text="ICMP:", font=("Arial", 12))
        self.icmp_label.pack(pady=5)

        # ICMP Type
        self.icmp_type = tk.Frame(self.icmp_frame)
        self.icmp_type.pack(pady=5, padx=5, fill="x")

        self.icmp_type_label = tk.Label(self.icmp_type, text="Тип:", font=("Arial", 14))
        self.icmp_type_label.pack(side="left", pady=5)

        self.icmp_type_var = tk.StringVar(value="request")  # request или reply
        self.icmp_type_combobox = ttk.Combobox(self.icmp_type, values=["reply", "request"], textvariable=self.icmp_type_var, state="readonly", width=10)
        self.icmp_type_combobox.pack(side="right", pady=1)

        # ICMP Code
        self.icmp_code = tk.Frame(self.icmp_frame)
        self.icmp_code.pack(pady=5, padx=5, fill="x")

        self.icmp_code_label = tk.Label(self.icmp_code, text="Code:")
        self.icmp_code_label.pack(side="left", padx=5)

        self.icmp_code_entry = tk.Entry(self.icmp_code, width=15)
        self.icmp_code_entry.insert(0, 0)  # Код ICMP (обычно 0 для ping)
        self.icmp_code_entry.pack(side="right", padx=5)

        # ICMP Checksum
        self.icmp_checksum = tk.Frame(self.icmp_frame)
        self.icmp_checksum.pack(pady=5, padx=5, fill="x")

        self.icmp_checksum_label = tk.Label(self.icmp_checksum, text="Checksum:")
        self.icmp_checksum_label.pack(side="left", padx=5)

        self.icmp_checksum_entry = tk.Entry(self.icmp_checksum, width=15)
        self.icmp_checksum_entry.insert(0, 0)  # 0 = автоматический расчет
        self.icmp_checksum_entry.pack(side="right", padx=5)

        # ICMP Identifier
        self.icmp_identifier = tk.Frame(self.icmp_frame)
        self.icmp_identifier.pack(pady=5, padx=5, fill="x")

        self.icmp_identifier_label = tk.Label(self.icmp_identifier, text="Identifier:")
        self.icmp_identifier_label.pack(side="left", padx=5)

        self.icmp_identifier_entry = tk.Entry(self.icmp_identifier, width=15)
        self.icmp_identifier_entry.insert(0, 1)  # ID процесса (для сопоставления запрос-ответ)
        self.icmp_identifier_entry.pack(side="right", padx=5)

        # ICMP Sequence Number
        self.icmp_sequence_num = tk.Frame(self.icmp_frame)
        self.icmp_sequence_num.pack(pady=5, padx=5, fill="x")

        self.icmp_sequence_number_label = tk.Label(self.icmp_sequence_num, text="Sequence Number:")
        self.icmp_sequence_number_label.pack(side="left", padx=5)

        self.icmp_sequence_number_entry = tk.Entry(self.icmp_sequence_num, width=15)
        self.icmp_sequence_number_entry.insert(0, 137)  # Номер последовательности
        self.icmp_sequence_number_entry.pack(side="right", padx=5)

        # ==================== ДАННЫЕ ПАКЕТА ====================
        self.input_data = tk.Frame(self.packet_frame)
        self.input_data.pack(side="right", pady=1, padx=5, fill="both", expand=True)

        self.input_data_label = tk.Label(self.input_data, text="Данные:")
        self.input_data_label.pack(padx=5)

        self.window_input_data = tk.Text(self.input_data, width=20, height=10)  # Многострочное поле для данных
        self.window_input_data.pack(pady=10, fill="both", expand=True)

        self.update_packet_fields()  # Показать поля для выбранного протокола

    def update_packet_fields(self, *args):
        """Показывает/скрывает поля в зависимости от выбранного протокола"""
        selected_protocol = self.protocol_var.get()  # Получить текущий протокол

        # Скрыть все фреймы протоколов
        self.tcp_frame.pack_forget()
        self.udp_frame.pack_forget()
        self.icmp_frame.pack_forget()

        # Показать нужный фрейм
        if selected_protocol == "TCP":
            self.tcp_frame.pack(pady=10, padx=10, fill="both", expand=True)
        elif selected_protocol == "UDP":
            self.udp_frame.pack(pady=10, padx=10, fill="both", expand=True)
        elif selected_protocol == "ICMP":
            self.icmp_frame.pack(pady=10, padx=10, fill="both", expand=True)


    def generate_packet(self):
        """Создает пакет из введенных параметров и добавляет в очередь"""
        packet = 0
        ip_source = self.ip_source_entry.get()  # IP источника
        ip_destination = self.ip_destination_entry.get()  # IP назначения
        protocol = self.protocol_var.get()  # Выбранный протокол

        # ========== ETHERNET ЗАГОЛОВОК ==========
        try:
            source_mac = self.get_mac()  # Получить MAC выбранного интерфейса
        except:
            print(f"Не удалось получить MAC-адрес для {ip_source}")
            return

        try:
            target_mac = getmacbyip(ip_destination)  # Получить MAC по IP (ARP запрос)
        except:
            print(f"Не удалось получить MAC-адрес для {ip_destination}")
            return
    
        ethernet_header = Ether(src=source_mac, dst=target_mac)  # Создать Ethernet заголовок

        # ========== IP ЗАГОЛОВОК ==========
        version_ip = 4  # Всегда IPv4
        ip_len_hd = int(self.ihl_var.get())  # Длина заголовка (в 32-битных словах)
        ip_tos = int(self.tos_entry.get())  # Тип обслуживания
        ip_len = int(self.total_len_entry.get())  # Общая длина пакета
        ip_id = int(self.id_entry.get())  # Идентификатор
        ip_offset = int(self.fragment_offset_entry.get())  # Смещение фрагмента
        ip_ttl = int(self.TTL_entry.get())  # Время жизни
        ip_checksum = int(self.check_sum_entry.get())  # Контрольная сумма
        
        # Создать IP заголовок (proto автоматически определится по следующему слою)
        ip_header = IP(dst=ip_destination, src=ip_source, version=version_ip, id=ip_id, ihl=ip_len_hd, tos=ip_tos, len=ip_len, frag=ip_offset, ttl=ip_ttl)
        packet = ethernet_header / ip_header  # Объединить Ethernet + IP

        # ========== TCP ЗАГОЛОВОК ==========
        if protocol == "TCP":
            source_port = int(self.tcp_source_port_entry.get())
            destination_port = int(self.tcp_destination_port_entry.get())
            seq_num = int(self.tcp_seq_num_entry.get())
            ack_num = int(self.tcp_ack_num_entry.get())
            data_offset = int(self.tcp_data_offset_entry.get())
            reserved = int(self.tcp_reserved_entry.get())
            
            # Собрать TCP флаги из чекбоксов
            tcp_flags = 0
            for i, flag in enumerate([self.check_var_fin.get(), self.check_var_syn.get(), self.check_var_rst.get(), self.check_var_psh.get(), self.check_var_ack.get(), self.check_var_urg.get()]):
                if flag == "on":
                    tcp_flags |= 1 << (i)  # Установить бит флага
            if tcp_flags == 0:
                tcp_flags = None  # Нет флагов
                
            window_size = int(self.tcp_window_size_entry.get())
            checksum = int(self.tcp_checksum_entry.get())
            urgent_pointer = int(self.tcp_urgent_pointer_entry.get())

            # Обработка специальных значений
            if data_offset == 0:
                data_offset = None  # Автоматический расчет
            if checksum == 0:
                checksum = None  # Автоматический расчет

            # Создать TCP заголовок
            tcp_header = TCP(sport=source_port, dport=destination_port, seq=seq_num, ack=ack_num, dataofs=data_offset, reserved=reserved, flags=tcp_flags, window=window_size, urgptr=urgent_pointer)
            packet = packet / tcp_header  # Добавить TCP к пакету

        # ========== UDP ЗАГОЛОВОК ==========
        elif protocol == "UDP":
            source_port = int(self.udp_source_port_entry.get())
            destination_port = int(self.udp_destination_port_entry.get())
            length = int(self.udp_length_entry.get())
            checksum = int(self.udp_checksum_entry.get())

            # Создать UDP заголовок
            udp_header = UDP(sport=source_port, dport=destination_port, len=length)
            packet = packet / udp_header  # Добавить UDP к пакету

        # ========== ICMP ЗАГОЛОВОК ==========
        elif protocol == "ICMP":
            type_str = self.icmp_type_var.get()
            code = int(self.icmp_code_entry.get())
            checksum = int(self.icmp_checksum_entry.get())
            identifier = int(self.icmp_identifier_entry.get())
            sequence_number = int(self.icmp_sequence_number_entry.get())
            
            # Преобразовать тип в число
            if type_str == "reply":
                type = 0  # Echo Reply
            else:
                type = 8  # Echo Request

            # Создать ICMP заголовок
            icmp_header = ICMP(type=type, code=code, id=identifier, seq=sequence_number)
            packet = packet / icmp_header  # Добавить ICMP к пакету

        # ========== ДАННЫЕ ==========
        input_data = self.window_input_data.get("1.0", "end-1c")  # Получить текст из поля
        packet = packet / input_data  # Добавить данные к пакету
        
        # Добавить в очередь
        self.packet_queue.append(packet)
        self.num_packets += 1
        self.info_packet.configure(text=str(self.num_packets))  # Обновить счетчик


    def send_packet(self):
        """Отправляет все пакеты из очереди"""
        print("click")
        for packet in self.packet_queue:
            print(self.int_var.get())  # Вывести имя интерфейса
            sendp(packet, iface=self.int_var.get(), verbose=0)  # Отправить на канальном уровне
            print(packet.show())  # Показать структуру пакета
        self.del_all_packet()  # Очистить очередь после отправки
            

    def del_packet(self):
        """Удаляет последний пакет из очереди"""
        self.packet_queue.pop()  # Удалить последний элемент
        self.num_packets -= 1
        self.info_packet.configure(text=str(self.num_packets))  # Обновить счетчик


    def del_all_packet(self):
        """Очищает всю очередь пакетов"""
        self.packet_queue[:] = []  # Очистить список
        self.num_packets = 0
        self.info_packet.configure(text=str(self.num_packets))  # Обнулить счетчик

    
    def get_connection_name_from_guid(self, iface_guids):
        """Преобразует GUID интерфейса в читаемое имя из реестра Windows"""
        iface_names = ['(unknown)' for i in range(len(iface_guids))]  # Список по умолчанию
        reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)  # Подключиться к реестру
        reg_key = wr.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')  # Ключ сетевых интерфейсов
        
        for i in range(len(iface_guids)):
            try:
                reg_subkey = wr.OpenKey(reg_key, iface_guids[i] + r'\Connection')  # Открыть подключ
                iface_names[i] = wr.QueryValueEx(reg_subkey, 'Name')[0]  # Прочитать имя
            except FileNotFoundError:
                pass  # Если GUID не найден в реестре
        return iface_names


    def get_mac(self):
        """Получает MAC-адрес выбранного сетевого интерфейса"""
        selected_value = self.int_var.get()  # Получить выбранное имя интерфейса
        
        # Найти индекс выбранного интерфейса
        for i, value in enumerate(self.x):
            if value == selected_value:
                index = i
                break
                
        ifaces = self.interfaces_all  # Список всех интерфейсов
        addrs = ni.ifaddresses(ifaces[index])  # Получить адреса интерфейса
        if ni.AF_LINK in addrs:  # Если есть канальный уровень (MAC)
            return addrs[ni.AF_LINK][0]['addr']  # Вернуть MAC-адрес


if __name__ == "__main__":
    app = PacketGeneratorApp()
    app.mainloop()
