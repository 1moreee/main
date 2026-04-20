import streamlit as st
import pandas as pd
import plotly.express as px

# ==========================================
# БЛОК 1: Об'єктно-орієнтована архітектура
# ==========================================
class NetworkAnalyzer:
    """
    Клас для інкапсуляції логіки аналізу мережевого трафіку.
    Приймає на вхід pandas DataFrame та виконує агрегацію даних.
    """
    def __init__(self, df: pd.DataFrame):
        self.df = df
        # Перевірка наявності потрібних колонок (Валідація даних)
        self.required_columns = {'Source IP', 'Destination IP', 'Protocol', 'Size (Bytes)'}
        if not self.required_columns.issubset(self.df.columns):
            raise ValueError(f"Файл не містить необхідних колонок. Очікуються: {self.required_columns}")

    def get_total_metrics(self) -> dict:
        """Повертає словник із загальною статистикою (структура даних: словник)."""
        total_packets = len(self.df)
        total_bytes = self.df['Size (Bytes)'].sum()
        
        # Демонстрація функціонального програмування (filter + lambda) та множин (set)
        # Збираємо всі унікальні IP-адреси (відправники та отримувачі)
        all_ips = list(self.df['Source IP']) + list(self.df['Destination IP'])
        unique_ips = set(filter(lambda ip: isinstance(ip, str) and ip.strip() != "", all_ips))
        
        return {
            "Кількість пакетів": total_packets,
            "Обсяг трафіку (Байт)": total_bytes,
            "Унікальних вузлів": len(unique_ips)
        }

    def get_top_ips(self, column: str = 'Source IP', top_n: int = 5) -> pd.DataFrame:
        """Повертає Топ-N IP-адрес за обсягом згенерованого трафіку."""
        top_ips = self.df.groupby(column)['Size (Bytes)'].sum().reset_index()
        top_ips = top_ips.sort_values(by='Size (Bytes)', ascending=False).head(top_n)
        return top_ips

    def get_protocol_distribution(self) -> pd.DataFrame:
        """Повертає розподіл трафіку за протоколами."""
        dist = self.df['Protocol'].value_counts().reset_index()
        dist.columns = ['Protocol', 'Packet Count']
        return dist

    def detect_anomalies(self, max_packets: int = 1000) -> list:
        """
        Пошук аномалій: повертає список IP-адрес (структура даних: список), 
        з яких надіслано підозріло багато пакетів.
        """
        packet_counts = self.df['Source IP'].value_counts()
        # Знаходимо IP, що перевищують поріг
        anomalous_ips = packet_counts[packet_counts > max_packets].index.tolist()
        return anomalous_ips

# ==========================================
# БЛОК 2: Інтерфейс веб-додатка (Streamlit)
# ==========================================
def main():
    # Налаштування сторінки
    st.set_page_config(page_title="Network Traffic Analyzer", page_icon="🛡️", layout="wide")
    st.title("🛡️ Аналізатор мережевої активності")
    st.markdown("Цей дашборд призначений для автоматизованого розбору логів мережевого трафіку та виявлення потенційних аномалій.")

    # Бокова панель для завантаження файлів
    st.sidebar.header("Налаштування")
    uploaded_file = st.sidebar.file_uploader("Завантажте лог-файл (CSV)", type=['csv'])

    if uploaded_file is not None:
        try:
            # Захист надійності: використання try-except для обробки помилок читання
            df = pd.read_csv(uploaded_file)
            
            # Ініціалізація нашого класу-аналізатора
            analyzer = NetworkAnalyzer(df)
            
            # 1. Виведення базових метрик
            st.header("1. Загальні показники")
            metrics = analyzer.get_total_metrics()
            col1, col2, col3 = st.columns(3)
            col1.metric("Всього пакетів", metrics["Кількість пакетів"])
            col2.metric("Загальний обсяг (Байт)", metrics["Обсяг трафіку (Байт)"])
            col3.metric("Унікальних вузлів", metrics["Унікальних вузлів"])
            
            # Відображення сирих даних (перші 100 рядків для оптимізації)
            with st.expander("Переглянути сирі дані (перші 100 записів)"):
                st.dataframe(df.head(100))

            # 2. Аналітика протоколів (Графік)
            st.header("2. Розподіл за протоколами")
            protocol_df = analyzer.get_protocol_distribution()
            fig_proto = px.pie(protocol_df, names='Protocol', values='Packet Count', 
                               title="Частка пакетів за протоколами", hole=0.4)
            st.plotly_chart(fig_proto, use_container_width=True)

            # 3. Аналіз джерел трафіку (Топ-5)
            st.header("3. Топ-5 активних вузлів")
            col_ip1, col_ip2 = st.columns(2)
            
            with col_ip1:
                st.subheader("Найбільші відправники")
                top_sources = analyzer.get_top_ips(column='Source IP')
                st.dataframe(top_sources)
                
            with col_ip2:
                st.subheader("Найбільші отримувачі")
                top_dest = analyzer.get_top_ips(column='Destination IP')
                st.dataframe(top_dest)

            # 4. Модуль виявлення аномалій (Безпека)
            st.header("4. Детектування аномалій")
            threshold = st.slider("Поріг аномальної кількості пакетів від одного IP:", min_value=100, max_value=5000, value=1000, step=100)
            
            anomalies = analyzer.detect_anomalies(max_packets=threshold)
            
            if anomalies:
                st.error(f"⚠️ Увага! Виявлено підозрілу активність. IP-адреси, що перевищили поріг ({threshold} пакетів):")
                for ip in anomalies:
                    st.write(f"— {ip}")
            else:
                st.success("✅ Аномалій не виявлено. Трафік у межах норми.")

        except pd.errors.EmptyDataError:
            st.error("Помилка: Завантажений файл порожній.")
        except ValueError as ve:
            st.error(f"Помилка структури файлу: {ve}")
        except Exception as e:
            st.error(f"Виникла непередбачувана помилка при обробці: {e}")
    else:
        st.info("Будь ласка, завантажте CSV-файл з мережевими даними через бокову панель ліворуч.")

if __name__ == "__main__":
    main()
