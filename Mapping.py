import argparse
import pandas as pd
from thefuzz import fuzz
import re
import os
from heuristic_rules import HEURISTIC_RULES

def read_table(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.xls', '.xlsx'):
        return pd.read_excel(path, dtype=str)
    elif ext == '.csv':
        return pd.read_csv(path, dtype=str, delimiter=';')
    else:
        raise ValueError("Unsupported file type: " + ext)

def normalize_columns_old(df):
    """Нормализация колонок для СТАРОГО списка угроз"""
    cols = {c.lower(): c for c in df.columns}
    
    mapping = {}
    
    # Ищем колонки по ключевым словам
    for pattern in ['идентификатор', 'уби']:
        for col in cols.keys():
            if pattern in col:
                mapping[cols[col]] = 'id'
                break
        if 'id' in mapping.values():
            break
    
    for pattern in ['наименование', 'название']:
        for col in cols.keys():
            if pattern in col:
                mapping[cols[col]] = 'name'
                break
        if 'name' in mapping.values():
            break
    
    for pattern in ['описание']:
        for col in cols.keys():
            if pattern in col:
                mapping[cols[col]] = 'description'
                break
        if 'description' in mapping.values():
            break
    
    # Если не нашли по паттернам, используем первые три колонки
    if len(mapping) < 3:
        available_cols = list(df.columns)
        if len(available_cols) >= 1:
            mapping[available_cols[0]] = 'id'
        if len(available_cols) >= 2:
            mapping[available_cols[1]] = 'name'  
        if len(available_cols) >= 3:
            mapping[available_cols[2]] = 'description'
    
    df = df.rename(columns=mapping)
    
    # Оставляем только нужные колонки
    result_cols = []
    for col in ['id', 'name', 'description']:
        if col in df.columns:
            result_cols.append(col)
        else:
            df[col] = ''  # Добавляем пустую колонку если не найдена
            result_cols.append(col)
    
    df = df[result_cols]
    df['description'] = df['description'].fillna('').astype(str)
    df['name'] = df['name'].fillna('').astype(str)
    df['id'] = df['id'].fillna('').astype(str)
    
    # Очистка данных
    df['name_clean'] = df['name'].str.lower()
    df['description_clean'] = df['description'].str.lower()
    
    return df

def normalize_columns_new(df):
    """Нормализация колонок для НОВОГО списка угроз"""
    cols = {c.lower(): c for c in df.columns}
    
    mapping = {}
    
    # Для нового списка ищем иерархические идентификаторы
    for pattern in ['идентификатор', 'код', 'id']:
        for col in cols.keys():
            if pattern in col:
                mapping[cols[col]] = 'id'
                break
        if 'id' in mapping.values():
            break
    
    for pattern in ['наименование', 'название', 'name']:
        for col in cols.keys():
            if pattern in col:
                mapping[cols[col]] = 'name'
                break
        if 'name' in mapping.values():
            break
    
    for pattern in ['описание', 'description']:
        for col in cols.keys():
            if pattern in col:
                mapping[cols[col]] = 'description'
                break
        if 'description' in mapping.values():
            break
    
    # Если не нашли по паттернам, используем логику по умолчанию
    if len(mapping) < 3:
        available_cols = list(df.columns)
        # Ищем колонку с паттерном X.Y.Z (иерархический ID)
        for i, col in enumerate(available_cols):
            sample_val = str(df[col].iloc[0]) if len(df) > 0 else ''
            if '.' in sample_val and all(part.isdigit() for part in sample_val.split('.')[:2]):
                mapping[col] = 'id'
                break
        
        for col in available_cols:
            if col not in mapping and 'наименование' in col.lower():
                mapping[col] = 'name'
                break
                
        for col in available_cols:
            if col not in mapping and 'описание' in col.lower():
                mapping[col] = 'description'
                break
        
        # Заполняем оставшиеся
        for col_type in ['name', 'description']:
            if col_type not in mapping.values():
                for col in available_cols:
                    if col not in mapping:
                        mapping[col] = col_type
                        break
    
    df = df.rename(columns=mapping)
    
    # Оставляем только нужные колонки
    result_cols = []
    for col in ['id', 'name', 'description']:
        if col in df.columns:
            result_cols.append(col)
        else:
            df[col] = ''  # Добавляем пустую колонку если не найдена
            result_cols.append(col)
    
    df = df[result_cols]
    df['description'] = df['description'].fillna('').astype(str)
    df['name'] = df['name'].fillna('').astype(str)
    df['id'] = df['id'].fillna('').astype(str)
    
    # Очистка данных
    df['name_clean'] = df['name'].str.lower()
    df['description_clean'] = df['description'].str.lower()
    
    return df

def extract_keywords(text):
    """Извлекаем ключевые слова из текста"""
    if not text:
        return set()
    
    # Удаляем стоп-слова и оставляем значимые слова
    words = re.findall(r'\b[а-яa-z]{4,}\b', text.lower())
    return set(words)

def heuristic_classification(text):
    """Эвристическая классификация на основе ключевых слов"""
    text_lower = text.lower()
    categories = set()
    
    for keyword, cats in HEURISTIC_RULES.items():
        if keyword in text_lower:
            categories.update(cats)
    
    return categories

def advanced_combined_score(old_row, new_row, new_categories):
    """Функция оценки с учетом эвристик"""
    # Базовые scores
    name_score = fuzz.token_set_ratio(old_row['name_clean'], new_row['name_clean'])
    desc_score = 0
    if old_row['description_clean'] and new_row['description_clean']:
        desc_score = fuzz.token_set_ratio(old_row['description_clean'], new_row['description_clean'])
    
    # Эвристический score
    heuristic_score = 0
    old_categories = heuristic_classification(old_row['name_clean'] + ' ' + old_row['description_clean'])
    
    if old_categories:
        # Проверяем, попадает ли новая угроза в одну из категорий старой
        new_id_prefix = '.'.join(new_row['id'].split('.')[:2]) + '.'  # Берем X.Y.
        if new_id_prefix in old_categories:
            heuristic_score = 100
        else:
            # Частичное совпадение категорий
            for cat in old_categories:
                if new_id_prefix.startswith(cat.split('.')[0] + '.'):  # Совпадение по основному классу
                    heuristic_score = 70
                    break
    
    # Ключевые слова
    keyword_score = 0
    old_keywords = extract_keywords(old_row['name_clean'] + ' ' + old_row['description_clean'])
    new_keywords = extract_keywords(new_row['name_clean'] + ' ' + new_row['description_clean'])
    
    if old_keywords and new_keywords:
        common_keywords = old_keywords.intersection(new_keywords)
        if common_keywords:
            keyword_score = min(100, len(common_keywords) * 20)
    
    # Комбинируем все scores
    base_score = 0.5 * name_score + 0.3 * desc_score + 0.2 * keyword_score
    final_score = max(base_score, heuristic_score)
    
    return final_score

def build_candidates_with_heuristics(old_df, new_df, topk=5):
    """Строим кандидатов с учетом эвристической классификации"""
    # Предварительно классифицируем новые угрозы
    print("Классификация новых угроз...")
    new_categories = {}
    for idx, new_row in new_df.iterrows():
        categories = heuristic_classification(new_row['name_clean'] + ' ' + new_row['description_clean'])
        new_categories[new_row['id']] = categories
    
    results = []
    
    print(f"Обрабатывается {len(old_df)} угроз из старого списка...")
    
    for i, old_row in old_df.iterrows():
        if i % 10 == 0:
            print(f"Обработано {i}/{len(old_df)}...")
        
        candidates = []
        old_categories = heuristic_classification(old_row['name_clean'] + ' ' + old_row['description_clean'])
        
        # Если есть эвристическая классификация, сначала ищем в соответствующих категориях
        prioritized_candidates = []
        other_candidates = []
        
        for idx, new_row in new_df.iterrows():
            score = advanced_combined_score(old_row, new_row, new_categories[new_row['id']])
            
            # Приоритет кандидатам из той же категории
            new_id_prefix = '.'.join(new_row['id'].split('.')[:2]) + '.'
            is_priority = any(new_id_prefix.startswith(cat.split('.')[0] + '.') for cat in old_categories) if old_categories else False
            
            candidate_data = (new_row['id'], new_row['name'], score)
            
            if is_priority and score > 30:
                prioritized_candidates.append(candidate_data)
            elif score > 20:
                other_candidates.append(candidate_data)
        
        # Сортируем и объединяем кандидатов
        prioritized_candidates.sort(key=lambda x: x[2], reverse=True)
        other_candidates.sort(key=lambda x: x[2], reverse=True)
        
        # Берем лучших кандидатов из приоритетных, затем из остальных
        all_candidates = prioritized_candidates[:topk] + other_candidates[:topk]
        all_candidates.sort(key=lambda x: x[2], reverse=True)
        final_candidates = all_candidates[:topk]
        
        results.append({
            'old_id': old_row['id'],
            'old_name': old_row['name'],
            'old_description': old_row['description'],
            'candidates': final_candidates,
            'old_categories': ', '.join(old_categories) if old_categories else 'не определены'
        })
    
    return results

def produce_mapping(candidates, threshold=60):
    """Создаем таблицу маппинга"""
    rows = []
    mapping_dict = {}
    
    for item in candidates:
        old_id = item['old_id']
        best = item['candidates'][0] if item['candidates'] else (None, None, 0)
        best_id, best_name, best_score = best
        
        status = 'no_match'
        if best_score >= threshold:
            status = 'auto'
            mapping_dict[old_id] = best_id
        elif best_score >= (threshold - 20):  # расширенная серая зона
            status = 'manual_review'
        else:
            status = 'no_match'
        
        # Сохраняем топ-k кандидатов
        topk_str = "; ".join([f"{cid}||{cname}||{round(score,1)}" for cid, cname, score in item['candidates']])
        rows.append({
            'old_id': old_id,
            'old_name': item['old_name'],
            'old_description': item['old_description'],
            'old_categories': item['old_categories'],
            'best_new_id': best_id,
            'best_new_name': best_name,
            'best_score': round(best_score, 2),
            'topk_candidates': topk_str,
            'mapping_status': status
        })
    
    return pd.DataFrame(rows), mapping_dict

def apply_overrides(mapping_dict, overrides_path):
    """Применяем ручные правки"""
    if not overrides_path:
        return mapping_dict
    
    df = read_table(overrides_path)
    cols = {c.lower(): c for c in df.columns}
    
    if 'old_id' not in cols or 'new_id' not in cols:
        raise ValueError("Overrides file must contain columns 'old_id' and 'new_id'")
    
    for idx, row in df.iterrows():
        mapping_dict[str(row[cols['old_id']])] = str(row[cols['new_id']])
    
    return mapping_dict

def main():
    parser = argparse.ArgumentParser(description='Улучшенный маппинг идентификаторов угроз ФСТЭК')
    parser.add_argument('--old', required=True, help='Путь к файлу старого списка (CSV или XLSX)')
    parser.add_argument('--new', required=True, help='Путь к файлу нового списка (CSV или XLSX)')
    parser.add_argument('--out', default='enhanced_mapping_result.xlsx', help='Файл результата маппинга')
    parser.add_argument('--threshold', type=float, default=60.0, help='Порог для авто-маппинга')
    parser.add_argument('--topk', type=int, default=5, help='Количество кандидатов для сохранения')
    parser.add_argument('--overrides', help='Файл с ручными правками маппинга')
    
    args = parser.parse_args()

    print("Чтение файлов...")
    
    old_df = normalize_columns_old(read_table(args.old))
    new_df = normalize_columns_new(read_table(args.new))
    
    print(f"Загружено {len(old_df)} угроз из старого списка")
    print(f"Загружено {len(new_df)} угроз из нового списка")
    
    print("\nПостроение кандидатов с эвристической классификацией...")
    candidates = build_candidates_with_heuristics(old_df, new_df, topk=args.topk)
    
    print("Создание таблицы маппинга...")
    mapping_df, mapping_dict = produce_mapping(candidates, threshold=args.threshold)

    # Применяем ручные правки если есть
    mapping_dict = apply_overrides(mapping_dict, args.overrides)

    # Сохраняем результат
    mapping_df.to_excel(args.out, index=False)
    print(f"\nРезультат маппинга сохранен в: {args.out}")
    
    # Статистика
    auto_count = len(mapping_df[mapping_df['mapping_status'] == 'auto'])
    review_count = len(mapping_df[mapping_df['mapping_status'] == 'manual_review'])
    no_match_count = len(mapping_df[mapping_df['mapping_status'] == 'no_match'])
    
    print(f"\nСтатистика маппинга:")
    print(f"  Автоматически сопоставлено: {auto_count} ({auto_count/len(mapping_df)*100:.1f}%)")
    print(f"  Требуют ручной проверки: {review_count} ({review_count/len(mapping_df)*100:.1f}%)") 
    print(f"  Не найдено соответствий: {no_match_count} ({no_match_count/len(mapping_df)*100:.1f}%)")

if __name__ == '__main__':
    main()