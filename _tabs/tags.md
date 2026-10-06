---
layout: page
title: Tags
permalink: /tags/
---

<div class="tag-cloud">
{% assign tags = site.posts | map: "tags" | join: "," | split: "," | uniq | sort %}
{% for tag in tags %}
  {% unless tag == "" %}<a href="#{{ tag | slugify }}">#{{ tag }}</a>{% endunless %}
{% endfor %}
</div>

{% for tag in tags %}
  {% unless tag == "" %}
  <h2 id="{{ tag | slugify }}">#{{ tag }}</h2>
  <ul>
  {% for post in site.posts %}
    {% if post.tags contains tag %}<li><a href="{{ post.url | relative_url }}">{{ post.title }}</a></li>{% endif %}
  {% endfor %}
  </ul>
  {% endunless %}
{% endfor %}
