<?php

/**
 * Created by PhpStorm.
 * Author: jwu049
 * Since: 2017/6/21 19:18
 */
class ContentCleaningUtil
{
    /**
     * 内容防xss攻击
     * @param $string
     * @param bool $low 过滤的等级
     * @return bool
     */
    public static function clean_xss(&$string, $low = false)
    {
        if (empty($string)) {
            return true;
        }
        if (!is_array($string)) {
            $string = trim($string);
            $string = strip_tags($string);
            $string = htmlspecialchars($string);
            if ($low) {
                return true;
            }
            $string = str_replace(array('"', "\\", "'", "/", "..", "../", "./", "//"), '', $string);
            $no = '/%0[0-8bcef]/';
            $string = preg_replace($no, '', $string);
            $no = '/%1[0-9a-f]/';
            $string = preg_replace($no, '', $string);
            //过滤XML标准规定的无效字节
            $no = '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/S';
            $string = preg_replace($no, '', $string);
            return true;
        }
        $keys = array_keys($string);
        foreach ($keys as $key) {
            self::clean_xss($string[$key]);
        }

        return true;
    }

    /**
     * 过滤掉
     * @param $content : 需要进行过滤的内容
     * @param $filter_word_list : 过滤词列表
     * @return mixed
     */
    public static function filterContentWithStar($content, $filter_word_list)
    {
        if (empty($content) || empty($filter_word_list)) {
            return $content;
        }

        foreach ($filter_word_list as $filter_word) {
            $filter_word = trim($filter_word);
            $word_length = mb_strlen($filter_word, 'UTF8');
            $content = str_replace($filter_word, implode('', array_fill(0, $word_length, "*")), $content);
        }

        return $content;
    }

    /**
     * @param $content : 需要过滤的内容
     * @param $filter_word : 过滤词
     * @param string $symbol : 过滤要替换掉的词
     * @return mixed
     */
    public static function filterContentWithSymbol($content, $filter_word, $symbol = '*')
    {
        if (empty($content) || empty($filter_word)) {
            return $content;
        }
        $filter_word = trim($filter_word);
        $word_length = mb_strlen($filter_word, 'UTF8');
        $content = str_replace($filter_word, implode('', array_fill(0, $word_length, $symbol)), $content);

        return $content;
    }
}
